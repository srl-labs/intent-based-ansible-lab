from ansible.plugins.action import ActionBase
from ansible.module_utils.basic import missing_required_lib
import traceback
import re

LXML_IMP_ERR = None
try:
    from lxml import etree
    HAS_LXML = True
except ImportError:
    HAS_LXML = False
    LXML_IMP_ERR = traceback.format_exc()


path_list_selector_re = re.compile(r"\[(?P<key>[^=]*?)=(?P<value>[^\]]*?)\](?=/|$|\[)")


def split_path(path):
    """
    Split a yang path into it's parts by splitting on `/`,
    taking into account a selector can also contain `/`!

    E.g.
    /port[port-id=1/1/c1]/connector ==> [ "port[port-id=1/1/c1]", "connector" ]
    """
    paths = []
    escapedpath = str(path)
    for match in path_list_selector_re.finditer(path):
        if "/" in match.group(0):
            escapedpath = str(escapedpath).replace(match.group(0), match.group(0).replace("/", "**SLASH**"))
    for p in escapedpath.split("/"):
        p = p.strip().replace("**SLASH**", "/")
        paths.append(p)
    paths = [p for p in paths if p != ""]
    return paths


def convert_path_to_xpath(path):
    """
    Converts yang paths to xpath, meaning:
    - turn multiple selectors into 1 with `and`
    - quoting selector values.

    E.g.
    /port[port-id=1/1/c1] ==> /port[port-id="1/1/c1"]
    """
    xpath = path
    selectors = []
    for selector in path_list_selector_re.finditer(xpath):
        xpath = xpath.replace(selector.group(0), "")
        selectors.append("%s=\"%s\"" % (selector["key"], selector["value"]))
    if len(selectors) > 0:
        xpath = xpath + "[%s]" % (" and ".join(selectors),)
    return xpath


def try_xpath(node, xpath, should_raise=True):
    if not isinstance(node, etree._Element):
        raise AttributeError(f"Node not an XMLElement! <{type(node).__name__}> {node}")
    try:
        return node.xpath(xpath)
    except Exception as e:
        if not should_raise:
            return []
        raise Exception(f"{type(e).__name__} exception occured with xpath '{xpath}' in xml '{etree.tostring(node)}'")


def navigate_path(path, root, create=False):
    """
    Navigates down a given `root` XMLElement using yang-path `path`
    and returns the destination XMLElement.
    If any of the nodes in the path does not exist, throws an exception,
    unless `create` == True, then they will be created.
    """
    path_elements = split_path(path)
    node = root
    for i in range(len(path_elements)):
        xpath = convert_path_to_xpath("/".join([".", *path_elements[:i+1]]))
        xpathmatch = try_xpath(root, xpath)
        if len(xpathmatch) != 1:
            if len(xpathmatch) == 0 and create:
                path2create = str(path_elements[i])
                for selector in path_list_selector_re.finditer(path2create):
                    path2create = (path2create.replace(selector.group(0), ""))
                node = etree.SubElement(node, path2create)
                for selector in path_list_selector_re.finditer(path_elements[i]):
                    n = etree.SubElement(node, selector["key"])
                    n.text = selector["value"]
                pass
            elif len(xpathmatch) == 0:
                raise Exception(f"Path not found {xpath}!")
            else:
                raise Exception(f"Xpath {xpath} ambiguous!")
        else:
            node = xpathmatch[0]
    return node


def set_value(value, node, tag=None):
    """
    Function to create XMLElements as children of the given `node` XMLElement
    with values from `value`.

    `value` of type dict become child XMLElements.
    To create multiple XMLElements with the same tag, use a dict with a list as value for the given tag key.
    `value` of type str become Text on the given XMLElement
    """
    if isinstance(value, dict):
        if tag is not None and isinstance(tag, str) and str(value.get('_tag', False)).lower() == "true":
            node.set("{urn:nokia.com:sros:ns:yang:sr:attributes}comment", tag)
        for key, val in value.items():
            if key == '_tag':
                continue
            if isinstance(val, list):
                if len(try_xpath(node, "./%s" % key)) > 0:
                    raise Exception("Can't merge new nodes with existing!")
                for v in val:
                    n = etree.SubElement(node, key)
                    set_value(v, n, tag=tag)
            else:
                n = navigate_path("./%s" % key, node, create=True)
                set_value(val, n, tag=tag)
    elif isinstance(value, str):
        node.text = value
    else:
        raise Exception(f"Invalid type {type(value).__name__}")


class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = {}

        result = super().run(tmp, task_vars)
        del tmp  # tmp no longer has any effect

        if not HAS_LXML:
            result["failed"] = True
            result["msg"] = missing_required_lib("lxml")
            result["exception"] = LXML_IMP_ERR
            return result

        # host_var = task_vars.get("groups", {})
        # argument = self._task.args.get("update", [])

        doc = etree.Element("{urn:ietf:params:xml:ns:netconf:base:1.0}config", nsmap={"nc": "urn:ietf:params:xml:ns:netconf:base:1.0"})
        configure = etree.SubElement(doc, "{urn:nokia.com:sros:ns:yang:sr:conf}configure",
                                     nsmap={"nokia-conf": "urn:nokia.com:sros:ns:yang:sr:conf",
                                            "nokia-attr": "urn:nokia.com:sros:ns:yang:sr:attributes"})

        nc_operation = {
            "update": "merge",
            "replace": "replace",
            "delete": "remove",
        }

        for operation in ["update", "replace", "delete"]:
            for entry in self._task.args.get(operation, []):
                node = navigate_path(entry["path"], configure, create=True)
                node.set("{urn:ietf:params:xml:ns:netconf:base:1.0}operation", nc_operation[operation])
                if operation in ["delete", "replace"]:
                    selectors = [selector["key"] for selector in path_list_selector_re.finditer(split_path(entry["path"])[-1])]
                    for c in node:
                        if c.tag not in selectors:
                            node.remove(c)
                    node.text = ""
                if operation in ["update", "replace"]:
                    set_value(entry["value"], node, tag="Ansible managed")

        result["xmlstring"] = etree.tostring(doc)
        return result
