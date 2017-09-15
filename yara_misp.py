# -*- coding: utf-8 -*-

import yara_validator as yaravalidator
import re
import six
import warnings
import psutil

from pymisp import PyMISP, PyMISPError, MISPAttribute
from yara_validator import YaraSource


FILENAME_TAG = '@yara-filename:'


class YaraMISPAttribute(MISPAttribute, YaraSource):

    def __init__(self, misp_attribute=None, **kwargs):

        MISPAttribute.__init__(self)
        if (misp_attribute and kwargs) or (not misp_attribute and not kwargs):
            raise SyntaxError("YaraMISPAttribute's constructor expects either "
                              "misp_attribute or **kwargs to be set")
        elif misp_attribute:
            if isinstance(misp_attribute, MISPAttribute):
                self.set_all_values(misp_attribute.__dict__)
            else:
                raise TypeError("YaraMISPAttribute's constructor expects "
                                "misp_attribute to be MISPAttribute, or None")
        else:
            self.set_all_values(**kwargs)
        YaraSource.__init__(self,
                            source=self._yaramisp_source,
                            namespace=str(self.event_id),
                            include_name=self._yaramisp_include_name)

    @property
    def _yaramisp_source(self):
        return attr_to_yara_source(self)

    @property
    def _yaramisp_include_name(self):
        if self.comment:
            regex = re.compile(r'^\s*'+FILENAME_TAG+'(.*)$', re.MULTILINE)
            match = regex.search(self.comment)
            return match.group(1).strip() if match else None
        else:
            return None

    def __str__(self):
        res = '// EVENT:     {}\n' \
              '// ATTRIBUTE: {}\n'.format(self.event_id, self.uuid)
        return res + YaraSource.__str__(self)


class YaraMISP:
    # Note on naming conventions:
    # 'attribute' represents a misp attribute (object) of type 'yara'
    # 'rule' represents a yara signature (string) or set of signatures

    @classmethod
    def _fetch_attrs(cls,
                     server,
                     key,
                     enforce_ids=True,
                     yara_only=True,
                     published_only=False,
                     include=None,
                     exclude=None):
        misp = PyMISP(server, key, True, 'json')
        if yara_only:
            type_attribute = ['yara']
        else:
            type_attribute = ['!'+exc for exc in
                              attributes_without_processing.keys()]
        yara_dict_attrs = []
        yara_pymisp_attrs = []

        ## FIXME : legacy code
        ## dirty fix for a missing feature (published filter unavailable
        ## on attributes search) and a bug in older MISP APIs (eventid and
        ## type_attribute cannot be both empty)
        if (not include and not type_attribute) or published_only is False:
            if not include:
                include = []
            all_events_dicts = misp.search_index(published=published_only)
            if 'errors' in all_events_dicts:
                raise PyMISPError(all_events_dicts['message'])
            for evt in all_events_dicts['response']:
                include.append(evt['id'])
            print('Index fetched ({})'.format(len(include)))
        search_results = misp.search(controller='attributes',
                                     type_attribute=type_attribute,
                                     to_ids=enforce_ids,
                                     eventid=include)
        if 'errors' in search_results:
            raise PyMISPError(search_results['message'])
        if search_results['response'] \
                and search_results['response']['Attribute']:
            yara_dict_attrs += search_results['response']['Attribute']

        ## end of dirty fix
        ## Once issues are fixed, replace with:
        # if not include:
        #     include = None
        # search_results = misp.search(controller='attributes',
        #                              type_attribute=type_attribute,
        #                              to_ids=enforce_ids,
        #                              eventid=include,
        #                              published=false)


        for attr in yara_dict_attrs:
            if not exclude or (attr['event_id'] not in exclude):
                misp_attribute = YaraMISPAttribute(**attr)
                yara_pymisp_attrs.append(misp_attribute)
        return yara_pymisp_attrs

    @classmethod
    def check_all(cls, **kwargs):
        attributes = kwargs['attributes'] if 'attributes' in kwargs else None
        server = kwargs['server'] if 'server' in kwargs else ''
        key = kwargs['key'] if 'key' in kwargs else None
        exclude_evts = kwargs['exclude_evts'] if 'exclude_evts' in kwargs \
            else []
        include_evts = kwargs['include_evts'] if 'include_evts' in kwargs \
            else []
        enforce_ids = kwargs['enforce_ids'] if 'enforce_ids' in kwargs \
            else True
        if (attributes and server and key) or \
                (not attributes and not (server and key)):
            raise Exception('yara_misp.check_all() requires either '
                            '("attributes") or ("server" and "key") '
                            'but not both')

        if not attributes:
            raw_yara_attributes_buffer = \
                cls._fetch_attrs(server,
                                 key,
                                 enforce_ids,
                                 True, # yara_only
                                 False, # published_only
                                 None, # include
                                 None) # exclude
        else:
            raw_yara_attributes_buffer = []
            for attr in attributes:
                if (not exclude_evts or attr.event_id not in exclude_evts) and \
                        (not include_evts or attr.event_id not in include_evts):
                    raw_yara_attributes_buffer.append(YaraMISPAttribute(attr))

        yara_validator = yaravalidator.YaraValidator(auto_clear=False)
        for attr in raw_yara_attributes_buffer:
            yara_validator.add_rule_source(attr)
        valid, broken, repaired = yara_validator.check_all()

        return valid, broken, repaired

# ================== ================== ================== ==================
# ============= Tools to build yara rules from non-yara attrs ===============
# ================== ================== ================== ==================

attributes_with_special_processing = {
    'yara': 'yara_rule_rule',
    'hex': 'single_hex_rule',
    'md5': 'hash_rule',
    'sha1': 'hash_rule',
    'sha256': 'hash_rule',
    'impash': 'hash_rule',
    'filename|md5': 'hash_rule',
    'filename|sha1': 'hash_rule',
    'filename|sha256': 'hash_rule',
    'filename|impash': 'hash_rule',
    'filename': 'filename_rule',
    # # 'size-in-bytes': filesize_rule,
    # partial support
    'filename|sha224': 'filename_partial_rule',
    'filename|sha384': 'filename_partial_rule',
    'filename|sha512': 'filename_partial_rule',
    'filename|sha512/224': 'filename_partial_rule',
    'filename|sha512/256': 'filename_partial_rule',
    'filename|ssdeep': 'filename_partial_rule',
    'filename|impfuzzy': 'filename_partial_rule',
    'filename|tlsh': 'filename_partial_rule',
    'filename|authentihash': 'filename_partial_rule',
    'ip-dst|port': 'host_port_rule',
    'ip-src|port': 'host_port_rule',
    'hostname|port': 'host_port_rule',
    'domain|ip': 'domaip_ip_rule'
}
attributes_without_processing = {
    # unsupported
    'sha224': 'ignore_rule_unsupported',
    'sha384': 'ignore_rule_unsupported',
    'sha512': 'ignore_rule_unsupported',
    'sha512/224': 'ignore_rule_unsupported',
    'sha512/256': 'ignore_rule_unsupported',
    'regkey|value': 'ignore_rule_unsupported',
    'malware-sample': 'ignore_rule_unsupported',
    'snort': 'ignore_rule_unsupported',
    'sigma': 'ignore_rule_unsupported',
    # irrelevant or too many false-positives expected
    'http-method': 'ignore_rule_irrelevant',
    'attachment': 'ignore_rule_irrelevant',
    'comment': 'ignore_rule_irrelevant',
    'link': 'ignore_rule_irrelevant',
}


def attr_to_yara_source(attr,
                        related_evt=None,
                        misp_url=None,
                        meta_blacklist=None):
    extra_meta = {}
    extra_meta['event_id'] = attr.event_id
    extra_meta['attr_uuid'] = attr.uuid
    extra_meta['comment'] = attr.comment
    extra_meta['category'] = attr.category
    extra_meta['type'] = attr.type
    if related_evt is not None:
        extra_meta['event_info'] = related_evt.event_info
    if misp_url is not None:
        extra_meta['event_link'] = misp_url + '/events/view/' + attr.event_id
    if meta_blacklist:
        for tag in meta_blacklist:
            del extra_meta[tag]

    if attr.type in attributes_with_special_processing:
        processing_func = globals()[
            attributes_with_special_processing[attr.type]]
        generated_yara = processing_func(attr, meta=extra_meta)
    elif attr.type in attributes_without_processing:
        processing_func = globals()[
            attributes_without_processing[attr.type]]
        generated_yara = processing_func(attr)
    else:
        generated_yara = single_hex_or_string_rule(attr, meta=extra_meta)

    return generated_yara


# -----HELPERS FOR RULES CONSTRUCTION ------------------------------------------
def basic_rule(attribute, strings_stmts, condition_stmts, **kwargs):
    if 'modules' not in kwargs or not kwargs['modules']:
        modules = []
    elif isinstance(kwargs['modules'], six.string_types):
        modules = [kwargs['modules']]
    else:
        modules = kwargs['modules']
    if isinstance(strings_stmts, six.string_types):
        strings_stmts = [strings_stmts]
    if isinstance(condition_stmts, six.string_types):
        condition_stmts = [condition_stmts]

    rulename = 'Attr_{}'.format(re.sub(r'\W+', '_', attribute.uuid))
    if 'meta' in kwargs and kwargs['meta'] is not None:
        meta_dict = kwargs['meta']
        meta = '\r\n\t\t'.join(
            [(key + ' = ' + text_str(str(meta_dict[key]))
              .replace('\n', ' ')
              .replace('\r', ' '))
             for key in meta_dict])
    else:
        meta = ''
    strings = '\r\n\t\t'.join(strings_stmts) if strings_stmts else ''
    condition = '\r\n\t\t'.join(condition_stmts) if condition_stmts else ''

    imports_section = '\r\n'.join(['import "{}"'.format(m) for m in modules]) \
        if modules else ''
    rule_start_section = 'rule ' + rulename + '{'
    meta_section = '\tmeta:\r\n\t\t' + meta
    strings_section = ('\tstrings:\r\n\t\t' + strings) if strings else ''
    condition_section = ('\tcondition:\r\n\t\t' + condition) if condition \
        else ''
    rule_end_section = '}'

    return '\r\n'.join([imports_section,
                        rule_start_section,
                        meta_section,
                        strings_section,
                        condition_section,
                        rule_end_section])


def text_str(str_ioc, ascii_wide_nocase=False):
    quoted = u'"{}"'.format(str_ioc.replace('\\', '\\\\').replace('"', '\\"'))
    if ascii_wide_nocase:
        return quoted + ' nocase ascii wide'
    else:
        return quoted


def hex_str(hex_ioc):
    trimmed_ioc = re.sub(r'\s', '', hex_ioc)
    trimmed_ioc = trimmed_ioc.strip('}"{\'')
    if all(c.upper() in '0123456789ABCDEF' for c in trimmed_ioc) and \
                    len(trimmed_ioc)%2==0 :
        timmed_spaced = " ".join(trimmed_ioc[i:i+2] for i in range(0, len(trimmed_ioc), 2))
        return '{ ' + timmed_spaced + ' }'
    else:
        raise ValueError('hex_str expects a string in hex format possibly '
                         'surrounded by curly brackets, spaces or quotes')


def hash_cond(hashtype, hashvalue):
    if hashtype in ['md5', 'sha1', 'sha256']:
        condition_stmt = 'hash.{}(0, filesize) == {}'\
            .format(hashtype, text_str(hashvalue.lower()))
        required_module = 'hash'
    elif hashtype is 'imphash':
        condition_stmt = 'pe.imphash() == ' + text_str(hashvalue.lower())
        required_module = 'pe'
    else:
        condition_stmt = ''
        required_module = None
        warnings.warn('Hash type "{}" unsupported'.format(hashtype))
    return condition_stmt, required_module


def pe_filename_cond(filename):
    return 'pe.version_info["OriginalFilename"] == ' + text_str(filename)


# ----- FUNCTIONS TO CONVERT ATTRIBUTES TO YARA RULES ACCORDING TO THEIR TYPE --

def yara_rule_rule(attribute, **kwargs):
    return attribute.value


def single_string_rule(attribute, **kwargs):
    strings_stmt = []
    i=0
    for line in attribute.value.splitlines():
        if line:
            strings_stmt += ['$ioc_l_{} = {}'.format(str(i),text_str(line, True))]
            i+=1
    condition_stmt = 'all of them'
    return basic_rule(attribute, strings_stmt, condition_stmt, **kwargs)


def single_hex_rule(attribute, **kwargs):
    strings_stmt = '$ioc = ' + hex_str(attribute.value)
    condition_stmt = '$ioc'
    return basic_rule(attribute, strings_stmt, condition_stmt, **kwargs)


def single_hex_or_string_rule(attribute, **kwargs):
    strings_stmt = []
    strings_id =[]
    i=0
    for line in attribute.value.splitlines():
        if line:
            strings_stmt += ['$ioc_l_{} = {}'.format(str(i),text_str(line, True))]
            strings_id += ['$ioc_l_'+str(i)]
            i+=1
    if len(strings_id)>1:
        condition_stmt = 'all of ({})'.format(', '.join(strings_id))
    else:
        condition_stmt = '$ioc_l_0'
    try:
        hex_value = hex_str(attribute.value)
        strings_stmt += ['$ioc_hex = ' + hex_value]
        condition_stmt += ' or $ioc_hex'
    except ValueError:
        pass
    return basic_rule(attribute, strings_stmt, condition_stmt, **kwargs)


def hash_rule(attribute, **kwargs):
    if attribute.type.startswith('filename|'):
        _, hashtype = attribute.type.rsplit('|', 1)
        filename, hashvalue = attribute.value.rsplit('|', 1)
        condition_stmt, required_module = hash_cond(hashtype, hashvalue)
        condition_stmt = condition_stmt + ' or ' + pe_filename_cond(filename)
        if required_module is not 'pe':
            required_module = [required_module, 'pe']
    else:
        hashtype = attribute.type
        hashvalue = attribute.value
        condition_stmt, required_module = hash_cond(hashtype, hashvalue)
    return basic_rule(attribute,
                      None,
                      condition_stmt,
                      modules=required_module,
                      **kwargs)


def filename_rule(attribute, **kwargs):
    condition_stmt = pe_filename_cond(attribute.value)
    return basic_rule(attribute, None, condition_stmt, modules='pe', **kwargs)


def filename_partial_rule(attribute, **kwargs):
    filename, _ = attribute.value.rsplit('|', 1)
    condition_stmt = pe_filename_cond(filename)
    return basic_rule(attribute, None, condition_stmt, modules='pe', **kwargs)


def host_port_rule(attribute, **kwargs):
    host, port = attribute.value.rsplit('|', 1)
    strings_stmt = ['$ioc_host_only = ' + text_str(host, True)]
    condition_stmt = '$ioc_host_only'
    return basic_rule(attribute, strings_stmt, condition_stmt, **kwargs)


def domaip_ip_rule(attribute, **kwargs):
    domain, ip = attribute.value.rsplit('|', 1)
    strings_stmt = ['$ioc_domain = ' + text_str(domain, True),
                    '$ioc_ip = ' + text_str(ip, True)]
    condition_stmt = '$ioc_domain and $ioc_ip'
    return basic_rule(attribute, strings_stmt, condition_stmt, **kwargs)


def ignore_rule(attribute, **kwargs):
    ignore_reason = ('//\t' + kwargs['ignore_reason']) \
        if 'ignore_reason' in kwargs else ''
    return '// Ignored attribute\r\n\
            //\tType: {}\r\n//\tuuid: {}\r\n{}'.format(attribute.type,
                                                       attribute.uuid,
                                                       ignore_reason)


def ignore_rule_unsupported(attribute, **kwargs):
    reason = 'IOC type "{}" is not supported by yara ' \
             'or any of its native modules'.format(attribute.type)
    return ignore_rule(attribute, ignore_reason=reason, **kwargs)


def ignore_rule_irrelevant(attribute, **kwargs):
    reason = 'Creating a yara IOC from a "{}" attribute does not make sense'\
        .format(attribute.type)
    return ignore_rule(attribute, ignore_reason=reason, **kwargs)
