import numpy as np
from matplotlib import pyplot as plt
from scipy import stats


def plot_durations(durations: list, name: str = ""):
    durations = [x for x in durations if x != 0]
    n_of_bins = int(np.sqrt(len(durations)))
    plt.figure()
    plt.hist(durations, bins=n_of_bins, density=True)
    plt.xlabel("Flow Duration (seconds)")
    plt.ylabel("probability density")
    plt.title("PDF of Flow Durations")
    plt.savefig(f"pdf_duration_{name}")


def plot_throughputs(throughputs: list, name: str = ""):
    log_min = np.log10(min(throughputs))
    log_max = np.log10(max(throughputs))
    n_of_bins = int(np.sqrt(len(throughputs)))
    bins = np.logspace(log_min, log_max, n_of_bins)

    plt.figure()
    plt.hist(
        throughputs, bins=bins, density=True, alpha=0.5, label="Data"
    )

    x = np.logspace(log_min, log_max, 1000)

    # fitting task
    params_invgauss = stats.invgauss.fit(throughputs, floc=0)
    pdf_invgauss = stats.invgauss.pdf(x, *params_invgauss)
    plt.plot(x, pdf_invgauss, label="Inverse Gaussian", linewidth=2)

    throughputs_array = np.array(throughputs)

    print(f"{'Distribution':<20} {'KS Statistic':>15} {'p-value':>15}")
    print("-" * 55)

    ks_stat, p_value = stats.kstest(
        throughputs_array, stats.invgauss.cdf, args=params_invgauss
    )

    print(f"ks statistics: {ks_stat:>15.4f} {p_value:>15.4f}")

    plt.xlabel("Throughput (bytes/sec)")
    plt.ylabel("Probability Density")
    plt.xscale("log")
    plt.title("PDF of Flow Throughput")
    plt.legend()  # show distribution names
    plt.savefig(f"pdf_throughput_{name}")


def plot_sizes(sizes_list: list, name: str = ""):
    n_of_bins = int(np.sqrt(len(sizes_list)))
    plt.figure()
    plt.hist(sizes_list, bins=n_of_bins, density=True)
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("probability density")
    plt.title("PDF of Packet Sizes")
    plt.savefig(f"pdf_packet_size_{name}")


def plot_inter_arrival_time(iats: list, name: str = ""):
    n_of_bins = int(np.sqrt(len(iats)))
    plt.figure()
    plt.hist(iats, bins=n_of_bins, density=True)
    plt.xlabel("Interarrival Time (seconds)")
    plt.ylabel("probability density")
    plt.title("PDF of Interarrival Times")
    plt.savefig(f"pdf_interarrival_times_{name}")
