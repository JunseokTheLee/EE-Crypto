import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# ------------------------------------------------------------
# Load data
# ------------------------------------------------------------

summary = pd.read_csv("results_summary.csv")
packets = pd.read_csv("results_packets.csv")

os.makedirs("figures", exist_ok=True)

# Actual loss rate experienced in each trial
summary["observed_loss_pct"] = (
    summary["packets_dropped"] / summary["packets_sent"] * 100
)


# ------------------------------------------------------------
# Recalculate cascade length
#
# A cascade:
# - starts after a network drop
# - counts only AUTH_FAIL or SILENT packets
# - does NOT count DROPPED packets
# - ends when an OK packet is received
# ------------------------------------------------------------

def calculate_cascade_lengths(trial):
    trial = trial.sort_values("seq")

    pending_loss = False
    active_cascade = False
    current_length = 0
    cascades = []

    for outcome in trial["outcome"]:

        if outcome == "DROPPED":
            # A loss can trigger a future cascade
            if not active_cascade:
                pending_loss = True

        elif outcome == "OK":
            # Successful decryption ends an active cascade
            if active_cascade:
                cascades.append(current_length)

            active_cascade = False
            current_length = 0
            pending_loss = False

        elif outcome in ["AUTH_FAIL", "SILENT"]:

            # First secondary failure after a network loss
            if pending_loss and not active_cascade:
                active_cascade = True
                current_length = 1
                pending_loss = False

            # Continue existing cascade
            elif active_cascade:
                current_length += 1

    # If stream ends during a cascade
    if active_cascade:
        cascades.append(current_length)

    return cascades


cascade_results = []

for trial_id, trial in packets.groupby("trial_id"):

    lengths = calculate_cascade_lengths(trial)

    cascade_results.append({
        "trial_id": trial_id,
        "corrected_mean_cascade":
            np.mean(lengths) if lengths else 0
    })

cascade_results = pd.DataFrame(cascade_results)

summary = summary.merge(cascade_results, on="trial_id")


# ------------------------------------------------------------
# Helper function: mean and SD for each experimental condition
# ------------------------------------------------------------

def process_metric(metric):

    return (
        summary
        .groupby(["scheme", "loss_type", "loss_rate_pct"])[metric]
        .agg(["mean", "std"])
        .reset_index()
    )


# Display names for graphs
scheme_names = {
    "AES-GCM": "AES-GCM",
    "AES-CBC": "AES-CBC",
    "AES-CBC-NOAUTH": "AES-CBC-NOAUTH"
}

loss_names = {
    "standard": "Standard",
    "burst": "Correlated"
}

markers = {
    "standard": "o",
    "burst": "s"
}

linestyles = {
    "standard": "-",
    "burst": "--"
}


# ============================================================
# FIGURE 1 — LOSS AMPLIFICATION FACTOR
# ============================================================

laf = process_metric("loss_amplification")

# Remove 0% because LAF is undefined
laf = laf[laf["loss_rate_pct"] > 0]

# CBC needs its own panel because its LAF is much larger
fig, axes = plt.subplots(2, 1, figsize=(7, 8))

# ---- AES-CBC ----

ax = axes[0]

for loss_type in ["standard", "burst"]:

    data = laf[
        (laf["scheme"] == "AES-CBC") &
        (laf["loss_type"] == loss_type)
    ]

    ax.errorbar(
        data["loss_rate_pct"],
        data["mean"],
        yerr=data["std"],
        marker=markers[loss_type],
        linestyle=linestyles[loss_type],
        capsize=4,
        label=loss_names[loss_type]
    )

ax.set_title("AES-CBC")
ax.set_ylabel("Loss Amplification Factor")
ax.set_xticks([10, 20, 30])
ax.grid(alpha=0.3)
ax.legend()


# ---- GCM and CBC-NOAUTH ----

ax = axes[1]

for scheme in ["AES-GCM", "AES-CBC-NOAUTH"]:

    for loss_type in ["standard", "burst"]:

        data = laf[
            (laf["scheme"] == scheme) &
            (laf["loss_type"] == loss_type)
        ]

        ax.errorbar(
            data["loss_rate_pct"],
            data["mean"],
            yerr=data["std"],
            marker=markers[loss_type],
            linestyle=linestyles[loss_type],
            capsize=4,
            label=f"{scheme_names[scheme]} — {loss_names[loss_type]}"
        )

ax.set_title("AES-GCM and AES-CBC-NOAUTH")
ax.set_xlabel("Configured Packet Loss Rate (%)")
ax.set_ylabel("Loss Amplification Factor")
ax.set_xticks([10, 20, 30])
ax.grid(alpha=0.3)
ax.legend()

fig.suptitle("Loss Amplification Factor vs Packet Loss Rate")
fig.tight_layout()

plt.savefig(
    "figures/figure1_loss_amplification.png",
    dpi=300,
    bbox_inches="tight"
)

plt.savefig(
    "figures/figure1_loss_amplification.pdf",
    bbox_inches="tight"
)

plt.close()


# ============================================================
# FIGURE 2 — MEAN CASCADE LENGTH
# ============================================================

cascade = process_metric("corrected_mean_cascade")

cascade = cascade[cascade["loss_rate_pct"] > 0]

fig, axes = plt.subplots(2, 1, figsize=(7, 8))

# ---- AES-CBC ----

ax = axes[0]

for loss_type in ["standard", "burst"]:

    data = cascade[
        (cascade["scheme"] == "AES-CBC") &
        (cascade["loss_type"] == loss_type)
    ]

    ax.errorbar(
        data["loss_rate_pct"],
        data["mean"],
        yerr=data["std"],
        marker=markers[loss_type],
        linestyle=linestyles[loss_type],
        capsize=4,
        label=loss_names[loss_type]
    )

ax.set_title("AES-CBC")
ax.set_ylabel("Mean Cascade Length (packets)")
ax.set_xticks([10, 20, 30])
ax.grid(alpha=0.3)
ax.legend()


# ---- GCM and NOAUTH ----

ax = axes[1]

for scheme in ["AES-GCM", "AES-CBC-NOAUTH"]:

    for loss_type in ["standard", "burst"]:

        data = cascade[
            (cascade["scheme"] == scheme) &
            (cascade["loss_type"] == loss_type)
        ]

        ax.errorbar(
            data["loss_rate_pct"],
            data["mean"],
            yerr=data["std"],
            marker=markers[loss_type],
            linestyle=linestyles[loss_type],
            capsize=4,
            label=f"{scheme_names[scheme]} — {loss_names[loss_type]}"
        )

ax.set_title("AES-GCM and AES-CBC-NOAUTH")
ax.set_xlabel("Configured Packet Loss Rate (%)")
ax.set_ylabel("Mean Cascade Length (packets)")
ax.set_xticks([10, 20, 30])
ax.grid(alpha=0.3)
ax.legend()

fig.suptitle("Mean Cascade Length vs Packet Loss Rate")
fig.tight_layout()

plt.savefig(
    "figures/figure2_cascade_length.png",
    dpi=300,
    bbox_inches="tight"
)

plt.savefig(
    "figures/figure2_cascade_length.pdf",
    bbox_inches="tight"
)

plt.close()


# ============================================================
# FIGURE 3 — EFFECTIVE THROUGHPUT
# ============================================================

throughput = process_metric("effective_throughput_kbps")

fig, axes = plt.subplots(1, 2, figsize=(11, 5), sharey=True)

# Separate standard and correlated loss
for ax, loss_type in zip(
    axes,
    ["standard", "burst"]
):

    for scheme in [
        "AES-GCM",
        "AES-CBC",
        "AES-CBC-NOAUTH"
    ]:

        data = throughput[
            (throughput["scheme"] == scheme) &
            (throughput["loss_type"] == loss_type)
        ]

        ax.errorbar(
            data["loss_rate_pct"],
            data["mean"],
            yerr=data["std"],
            marker="o",
            capsize=4,
            label=scheme_names[scheme]
        )

    ax.set_title(loss_names[loss_type] + " Loss")
    ax.set_xlabel("Configured Packet Loss Rate (%)")
    ax.set_xticks([0, 10, 20, 30])
    ax.grid(alpha=0.3)

axes[0].set_ylabel("Effective Throughput (KiB/s)")
axes[1].legend()

fig.suptitle("Effective Throughput vs Packet Loss Rate")
fig.tight_layout()

plt.savefig(
    "figures/figure3_effective_throughput.png",
    dpi=300,
    bbox_inches="tight"
)

plt.savefig(
    "figures/figure3_effective_throughput.pdf",
    bbox_inches="tight"
)

plt.close()

print("Graphs saved in the 'figures' folder.")