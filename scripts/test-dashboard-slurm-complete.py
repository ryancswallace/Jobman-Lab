#!/usr/bin/env python3
"""Offline fixed-scope observation checks; never connects to Slurm."""
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('complete',ROOT/'observe-dashboard-slurm-complete.py');observe=importlib.util.module_from_spec(spec);spec.loader.exec_module(observe)

class Scope(unittest.TestCase):
    def test_exact_preflight_and_no_scheduler_mutation_operation(self):
        self.assertEqual(observe.validate({'operation':'preflight'}),{'operation':'preflight'})
        for p in [{'operation':'cancel','parentId':'45'}, {'operation':'preflight','command':'scontrol'}, {'operation':'accounting','parentId':'45;touch /tmp/x','collectionId':'80000000-0000-4000-8000-000000000001'}]:
            with self.subTest(p=p),self.assertRaises(ValueError):observe.validate(p)

    def test_accounting_pins_collection_and_expanded_parent(self):
        p={'operation':'accounting','parentId':'999999999999999999','collectionId':'80000000-0000-4000-8000-000000000001'}
        self.assertEqual(observe.validate(p),p)
        self.assertIn('JobIDRaw%64,JobID%64',observe.REMOTE)
        for parent in ['0','01','1_2','1[0-4]','9999999999999999999']:
            with self.subTest(parent=parent),self.assertRaises(ValueError):observe.validate(dict(p,parentId=parent))

    def test_completion_reads_require_all_five_distinct_literal_executions(self):
        rows=[{'index':i,'executionId':'80000000-0000-4000-8000-00000000000'+str(i)} for i in range(5)]
        p={'operation':'completions','executions':rows}
        self.assertEqual(observe.validate(p),p)
        for changed in [rows[:4],rows+[rows[0]], [dict(v,index=0) for v in rows], [dict(v,executionId=rows[0]['executionId']) for v in rows]]:
            with self.subTest(changed=changed),self.assertRaises(ValueError):observe.validate(dict(p,executions=changed))
        rows[0]['executionId']='../../credentials.json'
        with self.assertRaises(ValueError):observe.validate(p)

    def test_observation_contract_has_no_token_inputs_or_mutation_commands(self):
        for operation in ['sbatch','scancel','scontrol','enroll','systemctl\',\'restart','systemctl\',\'stop']:
            self.assertNotIn(operation,observe.REMOTE)
        self.assertIn('os.O_NOFOLLOW',observe.REMOTE)
        self.assertIn('os.O_NONBLOCK',observe.REMOTE)
        self.assertIn("expected={'outcome':'failure','exitCode':7} if index==2",observe.REMOTE)
        self.assertIn('completionSHA256',observe.REMOTE)

if __name__=='__main__':unittest.main()
