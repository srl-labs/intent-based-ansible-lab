import re
import copy

from ansible.errors import AnsibleFilterError

def expand_ranges(a):

    CRIT_PATTERN = re.compile(r'^(?P<prefix>[^\{]+)\{(?P<crit>[^\}]+)\}(?P<suffix>.*)')
    RANGE_PATTERN = re.compile(r'^(?P<start>\d+)\.\.(?P<end>\d+)')

    def filter(d):
        if isinstance(d, dict):
                for k,v in dict(d).items():
                    m_c = CRIT_PATTERN.search(str(k))
                    if m_c:
                        crit = m_c.group('crit').split(',')
                        for c in crit:
                            m_r = RANGE_PATTERN.search(c)
                            if m_r:
                                for n in range(int(m_r.group('start')), int(m_r.group('end')) + 1):
                                    key = m_c.group('prefix') + str(n) + m_c.group('suffix')
                                    if key in d:
                                        d[key] |= copy.deepcopy(d[k])
                                    else:
                                        d[key] = copy.deepcopy(d[k])
                            else:
                                key = m_c.group('prefix') + c + m_c.group('suffix')
                                if key in d:
                                    d[key] |= copy.deepcopy(d[k])
                                else:
                                    d[key] = copy.deepcopy(d[k])
                        del d[k]                         
                    if isinstance(v, dict):
                        filter(v)
                    elif isinstance(v, list):
                        for e in copy.deepcopy(v):
                            if isinstance(e, dict):
                                filter(e)
                            else:
                                m_c = CRIT_PATTERN.search(str(e))
                                if m_c:
                                    crit = m_c.group('crit').split(',')
                                    for c in crit:
                                        m_r = RANGE_PATTERN.search(c)
                                        if m_r:
                                            for n in range(int(m_r.group('start')), int(m_r.group('end')) + 1):
                                                v.append(m_c.group('prefix')+str(n)+m_c.group('suffix'))
                                        else:
                                            v.append(m_c.group('prefix') + c + m_c.group('suffix'))
                                    v.remove(e)

    filter(a)
    return a

class FilterModule(object):
    def filters(self):
        return {
            'expand_ranges': expand_ranges,
        }
    
