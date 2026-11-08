"""Fixed Iris analysis tasks for the local Claude Code and Codex CLIs."""
import csv
import io

TASKS = {
    "Petal analyst": ("Claude Code", "Compare mean petal lengths by species."),
    "Sample auditor": ("Claude Code", "Check class balance and missing fields."),
    "Range analyst": ("Claude Code", "Report minimum and maximum sepal widths by species."),
    "Schema reviewer": ("Codex", "Describe the columns and their types."),
    "Duplicate checker": ("Codex", "Count repeated measurement rows."),
    "Summary writer": ("Codex", "Summarize petal width differences between species."),
}


def build_prompt(task, content):
    rows = list(csv.reader(io.StringIO(content)))
    species = rows[0][2:]
    header = "sepal_length,sepal_width,petal_length,petal_width,species"
    observations = [",".join(row[:4] + [species[int(row[4])]]) for row in rows[1:]]
    return (task + " Use only the supplied public data. Respond in two short sentences. "
            "Do not use tools. Measurements are in cm.\n" + header + "\n" + "\n".join(observations))


def cli_args(provider):
    if provider == "Claude Code":
        return ["claude", "-p", "--tools", "", "--output-format", "text"]
    return ["codex", "exec", "--skip-git-repo-check", "--sandbox", "read-only", "-"]
