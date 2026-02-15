import csv
import os
import asyncio
from sidecar.layers.keywords import KeywordLayer
from sidecar.layers.base import ScanContext

async def benchmark_keywords():
    # Load current settings to get phrases
    from sidecar.core.settings import get_settings
    settings = get_settings()
    
    layer = KeywordLayer(blocked_phrases=settings.L1_BLOCKED_PHRASES)
    
    # Path to prompt injections dataset
    csv_path = "tests/datasets/prompt_injections.csv"
    if not os.path.exists(csv_path):
        # Try parent directory if not found (for different run contexts)
        csv_path = "GateWayApsix/safellm/tests/datasets/prompt_injections.csv"
        if not os.path.exists(csv_path):
            print(f"Error: Dataset not found at {csv_path}")
            return

    total_unsafe = 0
    caught_unsafe = 0
    total_safe = 0
    false_positives = 0
    
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            text = row["text"]
            label = int(row["label"]) # 1 is unsafe, 0 is safe
            
            ctx = ScanContext(text=text)
            result = await layer.scan(ctx)
            
            if label == 1:
                total_unsafe += 1
                if not result.safe:
                    caught_unsafe += 1
            else:
                total_safe += 1
                if not result.safe:
                    false_positives += 1
                    print(f"FP: {text[:100]}")

    print("--- Keywords Layer Benchmark (Current) ---")
    print(f"Total Unsafe Prompts: {total_unsafe}")
    print(f"Caught by Keywords: {caught_unsafe} ({caught_unsafe/total_unsafe*100:.2f}%)")
    print(f"Total Safe Prompts: {total_safe}")
    print(f"False Positives: {false_positives} ({false_positives/total_safe*100:.2f}%)")
    print("------------------------------------------")

if __name__ == "__main__":
    asyncio.run(benchmark_keywords())
