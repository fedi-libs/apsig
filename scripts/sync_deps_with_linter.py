from pathlib import Path

import tomllib
import yaml

root_dir = Path(__file__).parent.parent

pyproject_path = root_dir / "pyproject.toml"
pre_commit_config_path = root_dir / ".pre-commit-config.yaml"

with open(pyproject_path, "rb") as fp:
    pyproject = tomllib.load(fp)

project_data = pyproject.get("project", {})
main_deps = project_data.get("dependencies", [])

# Get dev dependencies from dependency-groups in pyproject.toml
dep_groups = pyproject.get("dependency-groups", {})
dev_deps = []
# The 'dev' group includes 'auto', 'lint', and 'test'.
# We collect all dependencies from these groups.
for group_name in ["auto", "lint", "test"]:
    dev_deps.extend(dep_groups.get(group_name, []))

all_deps = sorted(list(set(main_deps + dev_deps)))

# Exclude pyrefly and ruff from the list of additional dependencies.
# These tools are the main entry points for the pre-commit hooks and
# their dependencies are managed by pre-commit itself.
excluded_packages = ["pyrefly", "ruff"]
filtered_deps = [
    dep for dep in all_deps
    if not any(dep.startswith(pkg) for pkg in excluded_packages)
]


# Check if .pre-commit-config.yaml exists before proceeding
if not pre_commit_config_path.exists():
    print("'.pre-commit-config.yaml' not found. Skipping.")
    exit()

with open(pre_commit_config_path, "r") as fp:
    pre_commit_config = yaml.safe_load(fp)

for repo in pre_commit_config.get("repos", []):
    for hook in repo.get("hooks", []):
        hook["additional_dependencies"] = filtered_deps

with open(pre_commit_config_path, "w") as fw:
    noalias_dumper = yaml.dumper.Dumper
    noalias_dumper.ignore_aliases = lambda self, data: True
    yaml.dump(
        pre_commit_config,
        fw,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        Dumper=noalias_dumper,
    )

print("Synced pre-commit dependencies successfully.")