"""
SecureAudit-AI — Garlic Bundle Constructor (AI Agent Module 4)
Mixes real audit requests (subsets flagged risky by Modules 1/2/3)
with decoy requests, so the TPA cannot tell which subsets the
owner actually considers risky. The TPA still verifies every
subset in the bundle (real and decoy alike) - decoys cost some
extra TPA computation, but that's the price of hiding the real
signal.

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


class GarlicBundler:
    """Constructs privacy-preserving bundles mixing real + decoy subset requests."""

    @staticmethod
    def construct_bundle(real_subset_ids, all_subset_ids, decoys_per_real=None, seed=None):
        """
        Args:
            real_subset_ids: list of subset_ids the owner actually wants checked.
            all_subset_ids: list of ALL available subset_ids (the universe to
                draw decoys from).
            decoys_per_real: how many decoys to add per real request.
            seed: random seed for reproducibility.

        Returns:
            {
                "bundle": [subset_id, ...] (shuffled, real + decoys mixed),
                "real_set": set of real_subset_ids (kept OWNER-SIDE only,
                    never sent to the TPA - used to interpret results later),
            }
        """
        if decoys_per_real is None:
            decoys_per_real = config.DECOYS_PER_REAL_REQUEST

        rng = random.Random(seed)

        available_decoys = [sid for sid in all_subset_ids if sid not in set(real_subset_ids)]

        num_decoys = min(len(available_decoys), decoys_per_real * len(real_subset_ids))
        decoys = rng.sample(available_decoys, num_decoys)

        bundle = list(real_subset_ids) + decoys
        rng.shuffle(bundle)

        return {
            "bundle": bundle,
            "real_set": set(real_subset_ids),
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
    real_subset_ids = [655, 115, 26, 760, 282]  # example: flagged by Module 1/3

    print("Testing at different decoys-per-real ratios (averaged over 2000 trials each):\n")

    for decoys_per_real in [1, 2, 4, 8]:
        bundle_info = GarlicBundler.construct_bundle(
            real_subset_ids, all_subset_ids,
            decoys_per_real=decoys_per_real, seed=config.RANDOM_SEED
        )

        result = simulate_adversary_guess(bundle_info, num_trials=2000, seed=config.RANDOM_SEED)

        print(f"decoys_per_real={decoys_per_real}: "
              f"bundle_size={result['bundle_size']}, "
              f"mean_accuracy={result['mean_adversary_accuracy']} (+/-{result['std_adversary_accuracy']}), "
              f"chance_baseline={result['chance_baseline']}, "
              f"advantage={result['adversary_advantage']}")