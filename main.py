from baseline import Baseline
import typer
from rich import print
from rich.table import Table
from rich.console import Console

from chids.conf.config import *
from chids.shared.constants import *
from chids.ML.test_model import Testing
from chids.utils.anomaly_vector import AnomalyVector
from chids.shared.misc import *

console = Console()
app = typer.Typer(pretty_exceptions_short=False)

@app.command()
def evaluate(seen_syscalls: str = typer.Option(..., "--ss"), seen_args:str  = typer.Option(..., "--sa"), freq_max:str = typer.Option(..., "--fm"),
             trained_model:str=typer.Option(..., "--tm"), thresh_list:str = typer.Option(..., "--tl"), normal_dir:str=typer.Option(..., "--ns"),
             exploit_dir:str=typer.Option(..., "--ms")):
    console.print(EVALUATION_INITIALIZER, style=STYLE, soft_wrap=False)

    detection_rate = []
    false_positive_rate = []
    fp = []
    fn = []
    tp = []
    tn = []
    _dir = normal_dir
    print("GET results_normal_scaps")
    results_normal_scaps = _get_evaluation_results(NORMAL, _dir, seen_syscalls, seen_args, freq_max, trained_model, thresh_list)
    print("GET results_exploit_scaps")
    results_exploit_scaps = _get_evaluation_results(EXPLOIT, _dir, seen_syscalls, seen_args, freq_max, trained_model, thresh_list)
    
    # fp = [], tn = [], tp = [], fn = []
    # for _, i in enumerate(zip(*results_normal_scaps)):
    #     print(f"i: {i}")
    #     # normal_len = len(i)
    #     fp.append(i.count(True))
    #     tn.append(i.count(False))
    #     false_positive_rate.append(i.count(True)/len(i))

    # for i, value in enumerate(zip(*results_exploit_scaps)):
    #     detection_rate.append(value.count(True)/len(value))
    #     tp.append(value.count(True))
    #     fn.append(value.count(False))

    for _, i in enumerate(zip(*results_normal_scaps)):
        # print("fp: ",i.count(True))
        # print("tn: ",len(i) - i.count(True))
        fp.append(i.count(True))
        tn.append(len(i) - i.count(True))
        false_positive_rate.append(i.count(True)/len(i))

    for _, i in enumerate(zip(*results_exploit_scaps)):
        # print("tp: ",i.count(True))
        # print("fn: ",len(i) - i.count(True))
        tp.append(i.count(True))
        fn.append(len(i) - i.count(True))
        detection_rate.append(i.count(True)/len(i))

    _print_results(detection_rate, false_positive_rate, fp, tn, tp, fn)



@app.command()
def baseline(input_dir_path: str = typer.Option(..., "--td"), output_dir_name: str = typer.Option(..., "--od")):
    console.print(TRAINING_INITIALIZER, style=STYLE, soft_wrap=False)
    # scaps = prepare_scaps(input_dir_path)
    SCENARIOS = [
    #   "CVE-2017-7529",
    #   "CVE-2014-0160",
    #   "CVE-2012-2122",
    #   "Bruteforce_CWE-307",
      "CVE-2020-23839",
    #   "CWE-89-SQL-injection",
    #   "PHP_CWE-434",
    #   "ZipSlip",
    #   "CVE-2018-3760",
    #   "CVE-2020-9484",
    #   "EPS_CWE-434",
    #   "CVE-2019-5418",
    #   "Juice-Shop",
    #   "CVE-2020-13942",
    #   "CVE-2017-12635_6"
    ]
    scaps = input_dir_path + SCENARIOS[0]
    seen_syscalls, seen_args, max_freq, model, thresh_list = Baseline(scaps).get_training_elements()

    output_table = Table(title=TRAINING_HEADERS)
    output_table.add_column("Number of training scaps", style="magenta")
    output_table.add_column("previously seen syscalls", style="magenta")
    output_table.add_column("previously seen arguments", style="magenta")
    output_table.add_column("Thresholds", style="magenta")
    output_table.add_row(str(len(scaps)), str(seen_syscalls)[1:-1], str(seen_args)[1:-1], str(thresh_list)[1:-1])

    print(output_table)
    save_file([seen_syscalls, seen_args, max_freq, thresh_list], model, output_dir_name)


def _get_evaluation_results(recording_type, _dir, seen_syscalls, seen_args, freq_max, trained_model, thresh_list):
    seen_syscalls = load_pickled_file(seen_syscalls)
    seen_args = load_pickled_file(seen_args)
    freq_max = load_pickled_file(freq_max)
    thresh_list = load_pickled_file(thresh_list)

    # scaps = prepare_scaps(_dir)
    SCENARIOS = [
    #   "CVE-2017-7529",
    #   "CVE-2014-0160",
    #   "CVE-2012-2122",
    #   "Bruteforce_CWE-307",
      "CVE-2020-23839",
    #   "CWE-89-SQL-injection",
    #   "PHP_CWE-434",
    #   "ZipSlip",
    #   "CVE-2018-3760",
    #   "CVE-2020-9484",
    #   "EPS_CWE-434",
    #   "CVE-2019-5418",
    #   "Juice-Shop",
    #   "CVE-2020-13942",
    #   "CVE-2017-12635_6"
    ]
    scaps = _dir + SCENARIOS[0]
    baseline_obj = Baseline(scaps)
    scaps_dfs = baseline_obj._scaps_to_dfs(TESTING, recording_type)
    traces = baseline_obj._get_scaps_traces(scaps_dfs)
    scaps_anomaly_vectors = AnomalyVector(traces, seen_syscalls, seen_args, freq_max).get_anomaly_vectors()
    results = Testing(trained_model, thresh_list).get_classifications(scaps_anomaly_vectors)

    return results

def _print_results(detection_rate, false_positive_rate, fp, tn, tp, fn):
    output_table = Table(title=EVALUATION_HEADER)
    output_table.add_column("Theta", style="magenta")
    output_table.add_column("Detection Rate", style="magenta")
    output_table.add_column("False Alarm Rate", style="magenta")
    output_table.add_column("FP", style="magenta")
    output_table.add_column("TN", style="magenta")
    output_table.add_column("TP", style="magenta")
    output_table.add_column("FN", style="magenta")

    zipped_result = zip(THETA_VALUES, detection_rate, false_positive_rate, fp, tn, tp, fn)

    for i in zipped_result:
        output_table.add_row(str(i[0]), str(i[1]), str(i[2]), str(i[3]), str(i[4]), str(i[5]), str(i[6]))

    print(output_table)





if __name__== "__main__" :
    app()