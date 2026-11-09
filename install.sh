#!/usr/bin/env bash
set -Eeuo pipefail

trap 'printf "Error: installation failed at line %s.\n" "$LINENO" >&2' ERR

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

for tool in git rsync uv mktemp mkdir rm; do
    command -v "$tool" >/dev/null 2>&1 || fail "Required tool not found: $tool"
done

script_path=${BASH_SOURCE[0]}
[[ $script_path == */* ]] || script_path=./$script_path
source_dir=$(cd -- "${script_path%/*}" && pwd -P)
target_dir='/home/iyue/.idapro/plugins/FridaTools'
cd -- "$source_dir"
[[ $(git rev-parse --is-inside-work-tree) == true ]] || fail 'Source must be a Git working tree.'
[[ -z $(git rev-parse --show-prefix) ]] || fail 'Script must be at the Git project root.'

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/fridatools-install.XXXXXXXX")
trap 'rm -rf -- "$work_dir"' EXIT

printf 'Selecting project files from %s\n' "$source_dir"
git ls-files --cached --others --exclude-standard -z > "$work_dir/candidates"
# --no-index applies current ignore rules even to tracked files. Verbose,
# non-matching output contains four NUL-delimited fields per candidate.
if git check-ignore --no-index --verbose --non-matching -z --stdin \
    < "$work_dir/candidates" > "$work_dir/checked"; then
    :
else
    status=$?
    # Git returns 1 when none of the candidates is ignored; that is not an error.
    [[ $status -eq 1 ]] || fail "Git ignore filtering failed (status $status)."
fi

file_count=0
while IFS= read -r -d '' ignore_source &&
      IFS= read -r -d '' ignore_line &&
      IFS= read -r -d '' pattern &&
      IFS= read -r -d '' path; do
    # A negated pattern explicitly includes a file. Always exclude Git metadata
    # and virtual environments, even if someone tracked or unignored them.
    [[ -z $pattern || $pattern == '!'* ]] || continue
    case /$path/ in
        */.git/*|*/.venv/*) continue ;;
    esac
    # Deleted tracked files are not installation inputs. Symlinks (including
    # dangling links) are copied as links, without following directory links.
    [[ -e $path || -L $path ]] || continue
    if [[ -d $path && ! -L $path ]]; then
        fail "Directory entry is unsupported (possibly a submodule): $path"
    fi
    [[ -f $path || -L $path ]] || fail "Unsupported file type: $path"
    printf '%s\0' "$path"
    file_count=$((file_count + 1))
done < "$work_dir/checked" > "$work_dir/files"

# Git does not list empty directories. rsync creates the listed files' parent
# directories and preserves directory/file permissions. Do not enable recursion:
# otherwise a directory entry could copy ignored descendants. Never delete extras.
printf 'Copying %s files to %s\n' "$file_count" "$target_dir"
mkdir -p -- "$target_dir"
# Compare content too: equal sizes and timestamps must not hide changed files.
rsync -a --checksum --no-recursive --dirs --from0 --files-from="$work_dir/files" -- \
    "$source_dir/" "$target_dir/"

printf 'Running uv sync in %s\n' "$target_dir"
cd -- "$target_dir"
uv sync
printf 'Installation completed: %s\n' "$target_dir"
