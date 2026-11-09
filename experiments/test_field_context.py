import importlib.util
from pathlib import Path
import unittest
import numpy as np

spec=importlib.util.spec_from_file_location('fc',Path(__file__).with_name('field_context.py'))
fc=importlib.util.module_from_spec(spec);spec.loader.exec_module(fc)

def row(ident,records,times=None,src=('a',1),dst=('b',2),value=100):
    return {'id':ident,'source':'x','records':records,'observed_times':times or list(map(float,records)),
            'src':src,'dst':dst,'bytes':bytes([value])*50*min(8,len(records))}

class FieldContextTests(unittest.TestCase):
    def test_mask_preserves_direction_slots_and_exact_field_positions(self):
        r=row('x',[1,2]);raw=fc.vector(r,2);masked=fc.vector(r,2,True)
        # Figure 3 fields: IP ID 2..3, IP checksum 7..8,
        # TCP seq+ack 9..16, TCP checksum 21..22, independently specified.
        expected={50*j+direction+k for j in range(2) for direction in (0,25)
                  for k in (2,3,7,8,9,10,11,12,13,14,15,16,21,22)}
        self.assertEqual(set(np.where(masked==0)[0]),expected)
        for i in set(range(100))-expected:self.assertEqual(masked[i],raw[i])
        self.assertEqual(r['bytes'],bytes([100])*100)

    def test_future_neighbor_packets_are_not_used(self):
        target=row('t',[5,10]);neighbor=row('n',[2,20],value=200)
        g,receipt=fc.graph(target,[target,neighbor],2)
        self.assertEqual(receipt['represented_records'],[10,2])
        self.assertTrue(np.all(g[0][1,50:]==0))
        neighbor['records'].append(30);neighbor['observed_times'].append(30.)
        after,_=fc.graph(target,[target,neighbor],2)
        for a,b in zip(g,after):np.testing.assert_array_equal(a,b)

    def test_unobserved_short_and_other_source_contexts(self):
        t=row('t',[5,10]);short=row('short',[8]);future=row('future',[11,12]);other=row('other',[3,4]);other['source']='y'
        _,r=fc.graph(t,[t,short,future,other],2)
        self.assertEqual(r['ids'],['t','short'])

    def test_self_arm_and_recent_context_cap(self):
        t=row('t',[99,100]);others=[row(str(i),[i],src=('a',1)) for i in range(1,99)]
        _,r=fc.graph(t,[t]+others,2,cap=4,window=10)
        self.assertEqual(r['ids'],['t','98','97','96'])
        g,r=fc.graph(t,[t]+others,2,context='self')
        self.assertEqual(g[0].shape,(1,100));self.assertEqual(r['neighbors'],0)
        self.assertTrue(np.all(g[2]==0))

if __name__=='__main__':unittest.main()
