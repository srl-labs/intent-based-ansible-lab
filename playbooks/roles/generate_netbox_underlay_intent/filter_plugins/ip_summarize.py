from functools import partial
from ansible.errors import AnsibleFilterError
from ansible.module_utils.basic import missing_required_lib

__metaclass__ = type

try:
    import netaddr
except ImportError:
    # in this case, we'll make the filters return error messages (see bottom)
    netaddr = None


def _need_netaddr(f_name, *args, **kwargs):
    """
    verify python's netaddr for these filters to work
    """
    raise AnsibleFilterError(missing_required_lib("netaddr"))


def summarize_cidrs(iterable, min_prefix_len=24):
    to_summarize = [netaddr.IPNetwork(e) for e in iterable]
    result = list(to_summarize)

    max_prefix_len = 0

    for ip in to_summarize:
        if ip.prefixlen < min_prefix_len:
            min_prefix_len = ip.prefixlen
        if ip.prefixlen > max_prefix_len:
            max_prefix_len = ip.prefixlen

    for prefixlen in range(max_prefix_len, min_prefix_len - 1, -1):
        merge_list = [ip.cidr for ip in to_summarize]
        for ip in merge_list:
            if ip.prefixlen > prefixlen:
                ip.prefixlen = prefixlen
        merge_result = netaddr.cidr_merge(merge_list)
        if len(merge_result) < len(result):
            result = merge_result

    return result


class FilterModule(object):

    filter_map = {
        "summarize_cidrs": summarize_cidrs,
    }

    def filters(self):
        if netaddr:
            return self.filter_map
        else:
            return dict((f, partial(_need_netaddr, f)) for f in self.filter_map)


if __name__ == "__main__":
    tests = [
            (["10.0.0.1/32", "10.0.0.2/32"],),
            (["10.0.0.1/24", "10.0.0.2/24"],),
            (["10.0.0.1/32", "10.128.0.1/32"],),
            (["10.0.0.1/32", "10.128.0.1/32"], 8,),
            (["10.0.0.1/32", "10.0.0.2/32", "192.168.255.1/32", "192.168.255.2/32"],),
    ]
    if netaddr:
        for test in tests:
            if len(test) == 1:
                print(f"{test[0]} summarizes to {summarize_cidrs(test[0])}")
            if len(test) == 2:
                print(f"{test[0]} (min_prefix_len={test[1]}) summarizes to {summarize_cidrs(test[0], min_prefix_len=test[1])}")
    else:
        print("Install netaddr first!")
