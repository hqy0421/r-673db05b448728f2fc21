import hashlib
import tempfile
import os
import sys
import shutil
import time

from warcio.archiveiterator import ArchiveIterator

import etl_plugin_core
from etl_file import Connector_File


# WARC-Profile of revisit records whose payload is identical to the payload
# of the record referenced by the WARC-Refers-To header (WARC 1.0 and 1.1)
revisit_profile_identical_payload_digest = 'revisit/identical-payload-digest'


# is the optional WARC revisit mode enabled by config option warc_revisit?
def warc_revisit_enabled(parameters):

    enabled = parameters.get('warc_revisit', False)

    # if set by command line parameter, the option is a string
    if isinstance(enabled, str):
        enabled = enabled.strip().lower() in ('1', 'true', 'yes', 'on')

    return bool(enabled)


class enhance_warc(etl_plugin_core.Plugin):

    # process plugin, if one of the filters matches
    filter_filename_suffixes = ['.warc', '.warc.gz']
    filter_mimetype_prefixes = ['application/warc']

    def process(self, parameters=None, data=None):
        if parameters is None:
            parameters = {}
        if data is None:
            data = {}

        verbose = False
        if 'verbose' in parameters:
            if parameters['verbose']:
                verbose = True

        # if this document was extracted from a WARC revisit record before,
        # add the id of the WARC response record the content was taken from
        if parameters.get('warc_source_record_id'):
            data['warc_source_record_id_s'] = parameters['warc_source_record_id']

        # no further processing, if plugin filters like for content type do not match
        if self.filter(parameters, data):
            return parameters, data

        warcfilename = parameters['filename']

        # create temp dir where to unwarc the archive
        if 'tmp' in parameters:
            system_temp_dirname = parameters['tmp']
            if not os.path.exists(system_temp_dirname):
                os.mkdir(system_temp_dirname)
        else:
            system_temp_dirname = tempfile.gettempdir()

        # we build temp dirname ourselfes instead of using system_temp_dirname so we can use configurable / external tempdirs
        h = hashlib.md5(parameters['id'].encode('UTF-8'))
        temp_dirname = system_temp_dirname + os.path.sep + \
            "opensemanticetl_enhancer_warc_" + h.hexdigest()

        if os.path.exists(temp_dirname) == False:
            os.mkdir(temp_dirname)

        # prepare document processing
        connector = Connector_File()
        connector.verbose = verbose
        connector.config = parameters.copy()

        # do not inherit the source record id of a WARC revisit record
        # this WARC file maybe was extracted from to its contained records
        # (it will be set explicitly for each contained revisit record)
        connector.config.pop('warc_source_record_id', None)

        # only set container if not yet set by a zip before (if this zip is inside another zip)
        if not 'container' in connector.config:
            connector.config['container'] = warcfilename

        if warc_revisit_enabled(parameters):
            # optional mode: index also revisit records, resolving their content
            # from the referenced response record(s)
            self.index_records_and_revisits(
                connector=connector, warcfilename=warcfilename, temp_dirname=temp_dirname, verbose=verbose)
        else:
            self.index_response_records(
                connector=connector, warcfilename=warcfilename, temp_dirname=temp_dirname)

        shutil.rmtree(temp_dirname)

        return parameters, data

    # index the content of all WARC response records (default)
    def index_response_records(self, connector, warcfilename, temp_dirname):

        i = 0

        with open(warcfilename, 'rb') as stream:
            for record in ArchiveIterator(stream):
                i += 1

                if record.rec_type == 'response':

                    print(record.rec_headers)

                    # write WARC record content to tempfile
                    tempfilename = temp_dirname + \
                        os.path.sep + 'warcrecord' + str(i)
                    tmpfile = open(tempfilename, 'wb')
                    tmpfile.write(record.content_stream().read())
                    tmpfile.close()

                    self.index_record(
                        connector=connector,
                        tempfilename=tempfilename,
                        uri=record.rec_headers.get_header('WARC-Target-URI'),
                        record_id=record.rec_headers.get_header('WARC-Record-ID'),
                        warc_date=record.rec_headers.get_header('WARC-Date'))

                    os.remove(tempfilename)

    # Optional mode (config option warc_revisit):
    # index not only WARC response records but also WARC revisit records
    # (profile identical-payload-digest with WARC-Refers-To header),
    # resolving their content from the final referenced response record,
    # even if the referenced record is stored before or after the revisit record
    # or the reference is a chain of multiple revisit records
    def index_records_and_revisits(self, connector, warcfilename, temp_dirname, verbose=False):

        records = []
        recordids = {}
        recordtypes = {}

        i = 0

        # stream the WARC file, extracting content of response records to temp files
        # and collecting metadata of revisit records, so that references can be resolved
        # even if the referenced record is stored after the revisit record in the WARC file
        with open(warcfilename, 'rb') as stream:
            for record in ArchiveIterator(stream):
                i += 1

                rec_type = record.rec_type
                record_id = record.rec_headers.get_header('WARC-Record-ID')

                # remember ids and types of all records for better error messages while resolving references
                if record_id and record_id not in recordtypes:
                    recordtypes[record_id] = rec_type

                if rec_type == 'response':
                    is_revisit = False
                elif rec_type == 'revisit' \
                        and record.rec_headers.get_header('WARC-Refers-To') \
                        and (record.rec_headers.get_header('WARC-Profile') or '').strip().endswith(
                            revisit_profile_identical_payload_digest):
                    is_revisit = True
                else:
                    # neither a response nor a supported revisit record
                    if verbose and rec_type == 'revisit':
                        print("Skipping WARC revisit record {} in {} since its WARC-Profile is not {} or no WARC-Refers-To header".format(
                            i, warcfilename, revisit_profile_identical_payload_digest))
                    continue

                uri = record.rec_headers.get_header('WARC-Target-URI')

                if not record_id or not uri:
                    sys.stderr.write("Skipping WARC record {} (type {}) in {}: missing WARC-Record-ID or WARC-Target-URI\n".format(
                        i, rec_type, warcfilename))
                    continue

                if record_id in recordids:
                    sys.stderr.write("Skipping WARC record {} (type {}) in {}: duplicate WARC-Record-ID {}\n".format(
                        i, rec_type, warcfilename, record_id))
                    continue

                info = {
                    'number': i,
                    'rec_type': rec_type,
                    'record_id': record_id,
                    'uri': uri,
                    'warc_date': record.rec_headers.get_header('WARC-Date'),
                }

                if is_revisit:
                    info['refers_to'] = record.rec_headers.get_header(
                        'WARC-Refers-To').strip()
                else:
                    # stream WARC record content to tempfile
                    tempfilename = temp_dirname + \
                        os.path.sep + 'warcrecord' + str(i)
                    with open(tempfilename, 'wb') as tmpfile:
                        shutil.copyfileobj(record.content_stream(), tmpfile)
                    info['tempfilename'] = tempfilename

                recordids[record_id] = info
                records.append(info)

        # resolve the references of the revisit records
        # to the final referenced response record
        for info in records:
            if info['rec_type'] == 'revisit':
                info['source'] = self.resolve_revisit(
                    revisit=info, recordids=recordids, recordtypes=recordtypes, warcfilename=warcfilename)

        # last record (in archive order) using each extracted tempfile,
        # so a tempfile can be deleted as soon as it is not needed anymore
        tempfiles_to_free = {}
        for pos, info in enumerate(records):
            if info['rec_type'] == 'response':
                tempfilename = info['tempfilename']
            elif info['source']:
                tempfilename = info['source']['tempfilename']
            else:
                continue
            tempfiles_to_free[tempfilename] = pos

        free_tempfiles_at = {}
        for tempfilename, last_pos in tempfiles_to_free.items():
            free_tempfiles_at.setdefault(last_pos, []).append(tempfilename)

        # index each valid record once in the order of records in the WARC file
        for pos, info in enumerate(records):

            if info['rec_type'] == 'revisit':

                source = info['source']

                # skip revisit records with unresolvable references (yet reported)
                if not source:
                    continue

                tempfilename = source['tempfilename']

                # tell ourself (while processing the extracted file)
                # which response record the content was taken from
                connector.config['warc_source_record_id'] = source['record_id']

            else:
                tempfilename = info['tempfilename']
                connector.config.pop('warc_source_record_id', None)

            self.index_record(
                connector=connector,
                tempfilename=tempfilename,
                uri=info['uri'],
                record_id=info['record_id'],
                warc_date=info['warc_date'])

            # delete tempfiles which are not needed anymore by upcoming records
            for tempfilename in free_tempfiles_at.get(pos, []):
                os.remove(tempfilename)

    # Follow the WARC-Refers-To reference(s) of a revisit record
    # (maybe a chain of multiple revisit records referencing each other)
    # to the final referenced WARC response record.
    # Returns None (and reports the reason to stderr), if the reference
    # can not be resolved (missing target or circular reference)
    def resolve_revisit(self, revisit, recordids, recordtypes, warcfilename):

        seen_recordids = [revisit['record_id']]
        current = revisit

        while current['rec_type'] == 'revisit':

            refers_to = current['refers_to']

            if refers_to in seen_recordids:
                sys.stderr.write("Skipping WARC revisit record {} ({}) in {}: circular reference of WARC-Refers-To to {}\n".format(
                    revisit['number'], revisit['record_id'], warcfilename, refers_to))
                return None

            seen_recordids.append(refers_to)

            target = recordids.get(refers_to)

            if target is None:
                if refers_to in recordtypes:
                    sys.stderr.write("Skipping WARC revisit record {} ({}) in {}: WARC-Refers-To target {} is a {} record, not a response or revisit record\n".format(
                        revisit['number'], revisit['record_id'], warcfilename, refers_to, recordtypes[refers_to]))
                else:
                    sys.stderr.write("Skipping WARC revisit record {} ({}) in {}: WARC-Refers-To target {} is missing in the WARC file\n".format(
                        revisit['number'], revisit['record_id'], warcfilename, refers_to))
                return None

            current = target

        return current

    # index the (extracted) content of a WARC record by the file indexing connector
    def index_record(self, connector, tempfilename, uri, record_id, warc_date):

        # set last modification time of the file to WARC-Date
        try:
            last_modified = time.mktime(time.strptime(
                warc_date, '%Y-%m-%dT%H:%M:%SZ'))
            os.utime(tempfilename, (last_modified, last_modified))
        except BaseException as e:
            sys.stderr.write("Exception while reading filedate to warc content {} from {} : {}\n".format(
                tempfilename, connector.config['container'], e))

        # set id (URL and WARC Record ID)
        if not uri.endswith('/'):
            uri += '/'
        connector.config['id'] = uri + record_id

        # index the extracted file
        try:

            connector.index_file(filename=tempfilename)

        except KeyboardInterrupt:
            raise KeyboardInterrupt

        except BaseException as e:
            sys.stderr.write("Exception while indexing warc content {} from {} : {}\n".format(
                tempfilename, connector.config['container'], e))
