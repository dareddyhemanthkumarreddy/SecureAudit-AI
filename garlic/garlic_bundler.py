"""
SecureAudit-AI — Garlic Bundle Constructor (AI Agent Module 4)
Mixes real audit requests (subsets flagged risky by Modules 1/2/3)
with decoy requests, so the TPA cannot tell which subsets the
owner actually considers risky. The TPA still verifies every
subset in the bundle (real and decoy alike) - decoys cost some
extra TPA computation, but that's the price of hiding the real
signal.

FIXED (post-integration finding, see progress_log.md): the
original design multiplied decoys_per_real by the real-request
count with no upper bound, which could saturate the bundle to
the ENTIRE file's subset count when Module 1's selection rate
was already high - eliminating the efficiency benefit. This
version caps total bundle size as a percentage of the file
(MAX_BUNDLE_PCT), scaling decoys down when the real-request
count is already large, rather than growing unbounded.

Named "garlic" after the layered/bundled-request idea from
anonymity networks (e.g. I2P's garlic routing) - NOTE: this is
an adapted concept for this project, not a direct reuse of an
established cloud-auditing technique. Frame it in the paper as
our own design choice, not as citing prior PDP/auditing literature
that uses this exact term.
"""

import random
import sys
import os
import statistics

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config

MAX_BUNDLE_PCT = 0.60  # bundle never exceeds 60% of total subsets by default


class GarlicBundler:
    """Constructs privacy-preserving bundles mixing real + decoy subset requests."""

    @staticmethod
    def construct_bundle(real_subset_ids, all_subset_ids, decoys_per_real=None,
                          max_bundle_pct=MAX_BUNDLE_PCT, seed=None):
        """
        Args:
            real_subset_ids: list of subset_ids the owner actually wants checked.
            all_subset_ids: list of ALL available subset_ids (the universe to
                draw decoys from).
            decoys_per_real: DESIRED decoys per real request - actual count
                may be scaled down to respect max_bundle_pct.
            max_bundle_pct: total bundle size (real + decoys) will never
                exceed this fraction of len(all_subset_ids). Prevents
                saturation to the full file when real-request count is large.
            seed: random seed for reproducibility.

        Returns:
            {
                "bundle": [subset_id, ...] (shuffled, real + decoys mixed),
                "real_set": set of real_subset_ids (kept OWNER-SIDE only,
                    never sent to the TPA - used to interpret results later),
                "decoys_requested": how many decoys we wanted,
                "decoys_actual": how many decoys we could actually fit,
                "capped": whether max_bundle_pct forced a reduction,
            }
        """
        if decoys_per_real is None:
            decoys_per_real = config.DECOYS_PER_REAL_REQUEST

        rng = random.Random(seed)

        total_subsets = len(all_subset_ids)
        real_count = len(real_subset_ids)
        max_bundle_size = int(total_subsets * max_bundle_pct)

        available_decoys = [sid for sid in all_subset_ids if sid not in set(real_subset_ids)]

        decoys_requested = decoys_per_real * real_count

        # Respect BOTH constraints: can't exceed what's available, AND
        # can't push total bundle size past max_bundle_pct of the file.
        max_decoys_by_availability = len(available_decoys)
        max_decoys_by_cap = max(0, max_bundle_size - real_count)

        decoys_actual = min(decoys_requested, max_decoys_by_availability, max_decoys_by_cap)
        decoys_actual = max(0, decoys_actual)

        decoys = rng.sample(available_decoys, decoys_actual) if decoys_actual > 0 else []

        bundle = list(real_subset_ids) + decoys
        rng.shuffle(bundle)

        return {
            "bundle": bundle,
            "real_set": set(real_subset_ids),
            "decoys_requested": decoys_requested,
            "decoys_actual": decoys_actual,
            "capped": decoys_actual < decoys_requested,
        }


def simulate_adversary_guess(bundle_info, num_trials=2000, seed=None):
    """
    Simulates a naive adversary who sees ONLY the bundle (list of
    subset_ids) - no metadata, no ordering info beyond what's in
    the bundle - and tries to guess which entries are real.

    Since subset_ids carry no inherent signal distinguishing real
    from decoy, the adversary's best strategy is essentially random
    guessing. We run MANY trials and average, since a single guess
    is too noisy (high variance with small sample sizes) to draw
    any real conclusion from.
    """
    rng = random.Random(seed)

    bundle = bundle_info["bundle"]
    real_set = bundle_info["real_set"]

    num_real = len(real_set)
    bundle_size = len(bundle)

    accuracies = []

    for _ in range(num_trials):
        guessed_real = set(rng.sample(bundle, min(num_real, bundle_size)))
        correct_guesses = len(guessed_real & real_set)
        accuracy = correct_guesses / num_real if num_real > 0 else 0
        accuracies.append(accuracy)

    mean_accuracy = statistics.mean(accuracies)
    std_accuracy = statistics.stdev(accuracies) if len(accuracies) > 1 else 0

    chance_baseline = num_real / bundle_size if bundle_size > 0 else 0

    return {
        "bundle_size": bundle_size,
        "num_real": num_real,
        "num_decoys": bundle_size - num_real,
        "num_trials": num_trials,
        "mean_adversary_accuracy": round(mean_accuracy, 4),
        "std_adversary_accuracy": round(std_accuracy, 4),
        "chance_baseline": round(chance_baseline, 4),
        "adversary_advantage": round(mean_accuracy - chance_baseline, 4),
    }


if __name__ == "__main__":
    all_subset_ids = list(range(1, 775))  # matches your 774 subsets from sample.pdf

    print("Testing small real-request scenario (privacy validation, as before):\n")
    real_subset_ids = [655, 115, 26, 760, 282]

    for decoys_per_real in [1, 2, 4, 8]:
        bundle_info = GarlicBundler.construct_bundle(
            real_subset_ids, all_subset_ids,
            decoys_per_real=decoys_per_real, seed=config.RANDOM_SEED
        )
        result = simulate_adversary_guess(bundle_info, num_trials=2000, seed=config.RANDOM_SEED)
        print(f"decoys_per_real={decoys_per_real}: bundle_size={result['bundle_size']}, "
              f"mean_accuracy={result['mean_adversary_accuracy']}, "
              f"advantage={result['adversary_advantage']}")

    print("\nTesting the saturation scenario that was previously broken (large real-request count):\n")
    large_real_set = list(range(1, 425))  # 424 real requests, matching the main.py finding

    for max_pct in [0.60, 0.80, 1.0]:
        bundle_info = GarlicBundler.construct_bundle(
            large_real_set, all_subset_ids,
            decoys_per_real=4, max_bundle_pct=max_pct, seed=config.RANDOM_SEED
        )
        print(f"max_bundle_pct={max_pct}: real={len(large_real_set)}, "
              f"decoys_requested={bundle_info['decoys_requested']}, "
              f"decoys_actual={bundle_info['decoys_actual']}, "
              f"final_bundle_size={len(bundle_info['bundle'])} / {len(all_subset_ids)} total, "
              f"capped={bundle_info['capped']}")