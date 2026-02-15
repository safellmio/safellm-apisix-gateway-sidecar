"""
TestVisualizer - Helper for standardized security test result presentation.
Compliant with .cursorrules (statuses: ✅ SAFE, ✅ UNSAFE, ❌ false-negative, ❌ false-positive).
"""

import time
import textwrap
import os

class TestVisualizer:
    """
    Helper for clean, standardized presentation of LLM security test results.
    Compliant with .cursorrules (statuses ✅ SAFE, ✅ UNSAFE, ❌ false-negative, ❌ false-positive).
    """

    COLORS = {
        "green": "\033[92m",
        "red": "\033[91m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "bold": "\033[1m",
        "reset": "\033[0m"
    }

    def __init__(self, title):
        self.title = title
        self.results = []
        self.start_time = time.time()

    def get_status_info(self, expected, actual_safe):
        """
        Returns status and color aligned with .cursorrules.
        """
        if actual_safe and expected == 'safe':
            return "✅ SAFE", self.COLORS["green"]
        elif not actual_safe and expected == 'unsafe':
            return "✅ UNSAFE", self.COLORS["green"]
        elif actual_safe and expected == 'unsafe':
            return "❌ false-negative", self.COLORS["red"]
        else:
            return "❌ false-positive", self.COLORS["red"]

    def add_result(self, name, prompt, expected, actual_safe, score, processing_time_ms):
        """
        Adds a test result.
        """
        status, color = self.get_status_info(expected, actual_safe)
        self.results.append({
            "name": name,
            "prompt": prompt,
            "status": status,
            "color": color,
            "score": score,
            "time": processing_time_ms
        })

    def print_table(self):
        """
        Prints a summary table with multi-line support (overflow).
        """
        print(f"\n{self.COLORS['bold']}{self.COLORS['blue']}📊 FINAL REPORT: {self.title}{self.COLORS['reset']}")
        width = 120
        separator = "=" * width
        print(separator)

        # Header
        header = f"{'ID':<3} | {'Status':<18} | {'Score':<7} | {'Time':<8} | {'Test Case / Prompt'}"
        print(f"{self.COLORS['bold']}{header}{self.COLORS['reset']}")
        print("-" * width)

        for i, res in enumerate(self.results, 1):
            full_content = f"{res['name']}: \"{res['prompt'][:255]}\""

            # Split prompt into lines (max 70 chars per line in table)
            wrapper = textwrap.TextWrapper(width=70)
            content_lines = wrapper.wrap(full_content)

            if not content_lines:
                content_lines = [""]

            # First line with data
            first_row = f"{i:<3} | {res['color']}{res['status']:<18}{self.COLORS['reset']} | {res['score']:<7.3f} | {res['time']:>6.1f}ms | {content_lines[0]}"
            print(first_row)

            # Subsequent prompt lines (overflow) with aligned vertical bars
            for extra_line in content_lines[1:]:
                print(f"{' ': <3} | {' ': <18} | {' ': <7} | {' ': <8} | {extra_line}")

        # Separator after each row (except the last if single-line)
        if not (len(self.results) > 0 and i == len(self.results) and len(wrapper.wrap(f"{self.results[-1]['name']}: \"{self.results[-1]['prompt']}\"")) == 1):
            print("-" * width)

        if len(self.results) > 0 and len(wrapper.wrap(f"{self.results[-1]['name']}: \"{self.results[-1]['prompt']}\"")) == 1:
             print("-" * width)

        # Stats
        total = len(self.results)
        successes = sum(1 for r in self.results if "✅" in r['status'])
        fails = total - successes
        avg_time = sum(r['time'] for r in self.results) / total if total > 0 else 0

        print(f"Summary: {self.COLORS['green']}Successes: {successes}{self.COLORS['reset']} | "
              f"{self.COLORS['red']}Failures: {fails}{self.COLORS['reset']} | "
              f"Avg time: {avg_time:.1f}ms")
        print(separator + "\n")

    def generate_failure_report(self, script_name: str, output_dir: str = None):
        """
        Automatically generates a .md report for false-positive and false-negative results.

        File name format: {script_name}_FAILS.md
        """
        # Find failures (false-positive and false-negative)
        failures = []
        for i, res in enumerate(self.results, 1):
            if "false-" in res['status']:
                failures.append({
                    "id": i,
                    "status": res['status'],
                    "name": res['name'],
                    "prompt": res['prompt'],
                    "score": res['score'],
                    "time": res['time']
                })

        if not failures:
            print("✅ No failures to report!")
            return

        # Prepare output file name
        base_name = script_name.replace('.py', '').replace('.md', '')
        if output_dir:
            output_file = os.path.join(output_dir, f"{base_name}_FAILS.md")
        else:
            output_file = f"{base_name}_FAILS.md"

        # Generate markdown content
        content = f"""# Security Failures - {self.title}

## Summary
- **Test date**: {time.strftime('%Y-%m-%d %H:%M:%S')}
- **Total failures**: {len(failures)}
- **Script**: `{script_name}`

## Failure Details

"""

        for failure in failures:
            failure_type = "false-positive" if "false-positive" in failure['status'] else "false-negative"

            content += f"""### Failure #{failure['id']}: {failure['name']}
**Failure type**: {failure_type}
**Status**: {failure['status']}
**Score**: {failure['score']:.3f}
**Processing time**: {failure['time']:.1f}ms

**Input prompt**:
```
{failure['prompt']}
```

**Recommendation**:
- Add this case to model training
- Analyze the root cause

---

"""

        # Add failure category summary
        false_positives = sum(1 for f in failures if "false-positive" in f['status'])
        false_negatives = sum(1 for f in failures if "false-negative" in f['status'])

        content += f"""## Failure Statistics
- **False-positive**: {false_positives} ({false_positives/len(failures)*100:.1f}%)
- **False-negative**: {false_negatives} ({false_negatives/len(failures)*100:.1f}%)

## Next Steps
1. Review each failure and determine the root cause
2. Update model configuration if needed
3. Add test cases to validation
4. Re-test after changes

---
*Automatically generated by TestVisualizer*
"""

        # Write file
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"📄 Failure report generated: {output_file}")
            print(f"   Found {len(failures)} failures to analyze")
        except Exception as e:
            print(f"❌ Error writing file {output_file}: {e}")
