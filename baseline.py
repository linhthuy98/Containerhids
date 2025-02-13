from multiprocessing import Pool
import itertools

from chids.ML.train_model import Training
from chids.conf.config import CHUNK_SIZE
from chids.utils.trace import Trace
from chids.utils.seen_args import SeenArgs
from chids.utils.seen_syscalls import SeenSyscalls
from chids.utils.anomaly_vector import AnomalyVector
from chids.helpers.sysdig import Sysdig

from dataloader.dataloader_factory import dataloader_factory
from dataloader.data_loader_2021 import RecordingType
from dataloader.direction import Direction
from chids.shared.constants import *
from chids.shared.exceptions import *

import pandas as pd
from tqdm import tqdm

class Baseline:
    def __init__(self, scaps):
        self.scaps = scaps

    def _seen_syscalls(self, scaps_dfs):
        ss_obj = SeenSyscalls(scaps_dfs)
        seen_syscalls = ss_obj.seen_syscalls()
        return seen_syscalls

    def _seen_args(self, scaps_dfs):
        sa_obj = SeenArgs(scaps_dfs)
        seen_args = sa_obj.seen_args()
        return seen_args

    def _get_scaps_traces(self, scaps_dfs):
        trace_obj = Trace(scaps_dfs)
        traces = trace_obj.trace()
        traces = list(filter(None, traces))
        return traces

    def _get_max_seq_freq(self, traces):
        merged_list_sequences = list(itertools.chain.from_iterable(traces))
        max_seq_freq =  max([len(sequence) for sequence in merged_list_sequences])
        return max_seq_freq

    def _get_anomaly_vectors(self, traces, seen_syscalls, seen_args, max_seq_freq):
        av_obj = AnomalyVector(traces, seen_syscalls, seen_args, max_seq_freq)
        all_anomaly_vectors = av_obj.get_anomaly_vectors()
        return all_anomaly_vectors


    def _scaps_to_dfs(self, data_key, recording_type = None):
        pool = Pool()
        # all_scaps_dfs = pool.map(Sysdig().process_scap, self.scaps, chunksize=CHUNK_SIZE)
        all_scaps_dfs = []
        dataloader = dataloader_factory(self.scaps, direction=Direction.CLOSE)
        print(f"dataloader: TRAIN: {len(dataloader.training_data())}, VALIDATION: {len(dataloader.validation_data())}, TEST: {len(dataloader.test_data())}")
        print(f"TEST: NORMAL: {len(dataloader.test_data(recording_type=RecordingType.NORMAL))}, ABNORMAL: NORMAL: {len(dataloader.test_data(recording_type=RecordingType.NORMAL_AND_ATTACK))}")
        data_parts = {
            'Training': dataloader.training_data(),
            'Validation': dataloader.validation_data(),
            'Test': {
                'Normal': dataloader.test_data(recording_type=RecordingType.NORMAL),
                'Normal and Attack': dataloader.test_data(recording_type=RecordingType.NORMAL_AND_ATTACK)
            }
        }
        print(f"recording_type: {recording_type}")
        if recording_type is not None:
            data = data_parts[data_key][recording_type]
        else: 
            data = data_parts[data_key]
        print(f"data length: {len(data)}, key: {data_key}")
        for recording in tqdm(data, 'data loading'.rjust(45), unit="recordings", smoothing=0):
            sysdig_evts = []  
            for syscall in recording.syscalls():
                # print(f"syscall: {syscall.syscall_line}")
                timestamp = str(syscall.timestamp_datetime())
                name = syscall.name()
                evt_info = syscall.syscall_line.split()
                args = list(evt_info[7:])
                evt = [timestamp, name, args]
                # print(f"evt: {evt}")
                sysdig_evts.append(evt)
            scap_df = pd.DataFrame(sysdig_evts, columns=COLUMNS)
            if not scap_df.empty:
                all_scaps_dfs.append(scap_df)

        # if scap_df.empty:
        #     raise NoSyscallsFound(recording)
            
        print(f"length: {len(all_scaps_dfs)}")
        return all_scaps_dfs

    def get_training_elements(self):
        scaps_dfs = self._scaps_to_dfs(TRAINING)
        # print(f"scaps_dfs: length: {len(scaps_dfs)}")
        seen_syscalls = self._seen_syscalls(scaps_dfs)
        seen_args = self._seen_args(scaps_dfs)
        traces = self._get_scaps_traces(scaps_dfs)
        max_freq = self._get_max_seq_freq(traces)
        anomaly_vectors = self._get_anomaly_vectors(traces, seen_syscalls, seen_args, max_freq)
        thresh_list, model = Training(anomaly_vectors).train_model()

        return seen_syscalls, seen_args, max_freq, model, thresh_list







