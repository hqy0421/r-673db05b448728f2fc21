#!/usr/bin/python3
# -*- coding: utf-8 -*-

import unittest
import unittest.mock

import contextlib
import hashlib
import io
import os
import shutil
import tempfile
import time

from io import BytesIO

from warcio.warcwriter import WARCWriter

import enhance_warc


REVISIT_PROFILE = 'http://netpreserve.org/warc/1.0/revisit/identical-payload-digest'
REVISIT_PROFILE_URI_AGNOSTIC = 'http://netpreserve.org/warc/1.0/revisit/uri-agnostic-identical-payload-digest'


# fake file indexing connector, only recording what would be indexed
class FakeConnectorFile(object):

    def __init__(self):
        self.verbose = False
        self.config = {}
        self.indexed = []

    def index_file(self, filename, additional_plugins=()):
        with open(filename, 'rb') as file:
            content = file.read()
        self.indexed.append({
            'id': self.config.get('id'),
            'filename': filename,
            'warc_source_record_id': self.config.get('warc_source_record_id'),
            'mtime': os.path.getmtime(filename),
            'content': content,
        })
        return {}, {}


def add_response(writer, uri, record_id, date, body):
    http = ('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n' + body).encode('utf-8')
    payload = BytesIO(http)
    record = writer.create_warc_record(
        uri, 'response', payload=payload, length=len(http),
        warc_headers_dict={'WARC-Record-ID': record_id, 'WARC-Date': date})
    writer.write_record(record)


def add_revisit(writer, uri, record_id, date, refers_to=None, profile=REVISIT_PROFILE):
    headers = {'WARC-Record-ID': record_id, 'WARC-Date': date}
    if profile:
        headers['WARC-Profile'] = profile
    if refers_to:
        headers['WARC-Refers-To'] = refers_to
    record = writer.create_warc_record(uri, 'revisit', warc_headers_dict=headers)
    writer.write_record(record)


# write a test WARC file with response records, revisit records (backward,
# forward and chained references) and broken records (duplicate id,
# missing reference target, circular references)
def write_test_warc(filename, gzip=False):
    with open(filename, 'wb') as stream:
        writer = WARCWriter(stream, gzip=gzip)

        warcinfo = writer.create_warcinfo_record(filename, {'software': 'test'})
        writer.write_record(warcinfo)
        warcinfo_id = warcinfo.rec_headers.get_header('WARC-Record-ID')

        add_response(writer, 'http://example.com/a', '<urn:uuid:r1>', '2020-01-01T00:00:00Z', 'content-r1')
        # revisit referencing an earlier response
        add_revisit(writer, 'http://example.com/a', '<urn:uuid:v1>', '2020-02-01T00:00:00Z', refers_to='<urn:uuid:r1>')
        # revisit referencing a later revisit which references an earlier response (chained reference)
        add_revisit(writer, 'http://example.com/a2', '<urn:uuid:v2>', '2020-02-02T00:00:00Z', refers_to='<urn:uuid:v3>')
        add_revisit(writer, 'http://example.com/a3', '<urn:uuid:v3>', '2020-02-03T00:00:00Z', refers_to='<urn:uuid:r1>')
        # revisit referencing a later response (forward reference)
        add_revisit(writer, 'http://example.com/fwd', '<urn:uuid:vfwd>', '2020-02-04T00:00:00Z', refers_to='<urn:uuid:r3>')
        add_response(writer, 'http://example.com/b', '<urn:uuid:r2>', '2020-01-02T00:00:00Z', 'content-r2')
        # revisit referencing a missing record
        add_revisit(writer, 'http://example.com/miss', '<urn:uuid:vmiss>', '2020-02-05T00:00:00Z', refers_to='<urn:uuid:missing>')
        # revisits referencing each other (circular reference)
        add_revisit(writer, 'http://example.com/cycle1', '<urn:uuid:vc1>', '2020-02-06T00:00:00Z', refers_to='<urn:uuid:vc2>')
        add_revisit(writer, 'http://example.com/cycle2', '<urn:uuid:vc2>', '2020-02-07T00:00:00Z', refers_to='<urn:uuid:vc1>')
        # response with duplicate WARC-Record-ID
        add_response(writer, 'http://example.com/dup', '<urn:uuid:r1>', '2020-01-04T00:00:00Z', 'content-dup')
        # revisit with unsupported profile
        add_revisit(writer, 'http://example.com/other', '<urn:uuid:vother>', '2020-02-08T00:00:00Z', refers_to='<urn:uuid:r1>', profile=REVISIT_PROFILE_URI_AGNOSTIC)
        # revisit without WARC-Refers-To header
        add_revisit(writer, 'http://example.com/noref', '<urn:uuid:vnoref>', '2020-02-09T00:00:00Z', refers_to=None)
        # revisit referencing a warcinfo (not a response/revisit) record
        add_revisit(writer, 'http://example.com/warcinfo', '<urn:uuid:vwarcinfo>', '2020-02-10T00:00:00Z', refers_to=warcinfo_id)
        add_response(writer, 'http://example.com/c', '<urn:uuid:r3>', '2020-01-03T00:00:00Z', 'content-r3')


class Test_enhance_warc_revisit(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.connector = FakeConnectorFile()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def process_warc(self, warcfilename, parameters=None):
        if parameters is None:
            parameters = {}
        parameters['filename'] = warcfilename
        parameters['id'] = warcfilename
        parameters['tmp'] = self.tmpdir

        plugin = enhance_warc.enhance_warc()

        self.stderr = io.StringIO()
        self.stdout = io.StringIO()
        with unittest.mock.patch.object(enhance_warc, 'Connector_File', lambda *args, **kwargs: self.connector):
            with contextlib.redirect_stderr(self.stderr), contextlib.redirect_stdout(self.stdout):
                plugin.process(parameters=parameters, data={})

        return self.connector.indexed

    def temp_dirname(self, warcfilename):
        h = hashlib.md5(warcfilename.encode('UTF-8'))
        return self.tmpdir + os.path.sep + 'opensemanticetl_enhancer_warc_' + h.hexdigest()

    def test_revisit_mode(self):
        warcfilename = self.tmpdir + os.path.sep + 'test.warc'
        write_test_warc(warcfilename, gzip=False)

        indexed = self.process_warc(warcfilename, parameters={'warc_revisit': True})

        # each valid record indexed exactly once, in archive order
        ids = [doc['id'] for doc in indexed]
        self.assertEqual(ids, [
            'http://example.com/a/<urn:uuid:r1>',
            'http://example.com/a/<urn:uuid:v1>',
            'http://example.com/a2/<urn:uuid:v2>',
            'http://example.com/a3/<urn:uuid:v3>',
            'http://example.com/fwd/<urn:uuid:vfwd>',
            'http://example.com/b/<urn:uuid:r2>',
            'http://example.com/c/<urn:uuid:r3>',
        ])

        by_id = {}
        for doc in indexed:
            by_id[doc['id']] = doc

        # content of revisits taken from the final referenced response record
        self.assertEqual(by_id['http://example.com/a/<urn:uuid:r1>']['content'], b'content-r1')
        self.assertEqual(by_id['http://example.com/a/<urn:uuid:v1>']['content'], b'content-r1')
        # chained reference revisit -> revisit -> response
        self.assertEqual(by_id['http://example.com/a2/<urn:uuid:v2>']['content'], b'content-r1')
        self.assertEqual(by_id['http://example.com/a3/<urn:uuid:v3>']['content'], b'content-r1')
        # forward reference to a later response
        self.assertEqual(by_id['http://example.com/fwd/<urn:uuid:vfwd>']['content'], b'content-r3')

        # id of the response record the content was taken from
        self.assertEqual(by_id['http://example.com/a/<urn:uuid:v1>']['warc_source_record_id'], '<urn:uuid:r1>')
        self.assertEqual(by_id['http://example.com/a2/<urn:uuid:v2>']['warc_source_record_id'], '<urn:uuid:r1>')
        self.assertEqual(by_id['http://example.com/a3/<urn:uuid:v3>']['warc_source_record_id'], '<urn:uuid:r1>')
        self.assertEqual(by_id['http://example.com/fwd/<urn:uuid:vfwd>']['warc_source_record_id'], '<urn:uuid:r3>')
        # response records have no source record id
        self.assertEqual(by_id['http://example.com/a/<urn:uuid:r1>']['warc_source_record_id'], None)
        self.assertEqual(by_id['http://example.com/b/<urn:uuid:r2>']['warc_source_record_id'], None)

        # each revisit is indexed with its own WARC-Date as modification time
        expected_mtime = time.mktime(time.strptime('2020-02-01T00:00:00Z', '%Y-%m-%dT%H:%M:%SZ'))
        self.assertAlmostEqual(by_id['http://example.com/a/<urn:uuid:v1>']['mtime'], expected_mtime, places=4)
        expected_mtime = time.mktime(time.strptime('2020-02-04T00:00:00Z', '%Y-%m-%dT%H:%M:%SZ'))
        self.assertAlmostEqual(by_id['http://example.com/fwd/<urn:uuid:vfwd>']['mtime'], expected_mtime, places=4)

        # broken records skipped and reported, while other records were imported
        stderr = self.stderr.getvalue()
        self.assertIn('duplicate WARC-Record-ID', stderr)
        self.assertIn('missing in the WARC file', stderr)
        self.assertIn('circular reference', stderr)
        self.assertIn('not a response or revisit record', stderr)

        # temp dir and temp files cleaned up
        self.assertFalse(os.path.exists(self.temp_dirname(warcfilename)))

    def test_revisit_mode_gzip(self):
        warcfilename = self.tmpdir + os.path.sep + 'test.warc.gz'
        write_test_warc(warcfilename, gzip=True)

        indexed = self.process_warc(warcfilename, parameters={'warc_revisit': True})

        ids = [doc['id'] for doc in indexed]
        self.assertEqual(ids, [
            'http://example.com/a/<urn:uuid:r1>',
            'http://example.com/a/<urn:uuid:v1>',
            'http://example.com/a2/<urn:uuid:v2>',
            'http://example.com/a3/<urn:uuid:v3>',
            'http://example.com/fwd/<urn:uuid:vfwd>',
            'http://example.com/b/<urn:uuid:r2>',
            'http://example.com/c/<urn:uuid:r3>',
        ])

        by_id = {}
        for doc in indexed:
            by_id[doc['id']] = doc

        self.assertEqual(by_id['http://example.com/a2/<urn:uuid:v2>']['content'], b'content-r1')
        self.assertEqual(by_id['http://example.com/fwd/<urn:uuid:vfwd>']['warc_source_record_id'], '<urn:uuid:r3>')

        self.assertFalse(os.path.exists(self.temp_dirname(warcfilename)))

    def test_revisit_mode_enabled_by_string_parameter(self):
        warcfilename = self.tmpdir + os.path.sep + 'test.warc'
        write_test_warc(warcfilename, gzip=False)

        # if set by command line parameter, the option is a string
        indexed = self.process_warc(warcfilename, parameters={'warc_revisit': 'true'})

        ids = [doc['id'] for doc in indexed]
        self.assertIn('http://example.com/a/<urn:uuid:v1>', ids)

    def test_default_mode_unchanged(self):
        warcfilename = self.tmpdir + os.path.sep + 'test.warc'
        write_test_warc(warcfilename, gzip=False)

        # without the option warc_revisit only response records are indexed
        indexed = self.process_warc(warcfilename)

        ids = [doc['id'] for doc in indexed]
        self.assertEqual(ids, [
            'http://example.com/a/<urn:uuid:r1>',
            'http://example.com/b/<urn:uuid:r2>',
            'http://example.com/dup/<urn:uuid:r1>',
            'http://example.com/c/<urn:uuid:r3>',
        ])

        for doc in indexed:
            self.assertEqual(doc['warc_source_record_id'], None)

        self.assertFalse(os.path.exists(self.temp_dirname(warcfilename)))

    def test_warc_revisit_enabled(self):
        self.assertTrue(enhance_warc.warc_revisit_enabled({'warc_revisit': True}))
        self.assertTrue(enhance_warc.warc_revisit_enabled({'warc_revisit': 'true'}))
        self.assertTrue(enhance_warc.warc_revisit_enabled({'warc_revisit': 'True'}))
        self.assertTrue(enhance_warc.warc_revisit_enabled({'warc_revisit': '1'}))
        self.assertFalse(enhance_warc.warc_revisit_enabled({'warc_revisit': False}))
        self.assertFalse(enhance_warc.warc_revisit_enabled({'warc_revisit': 'false'}))
        self.assertFalse(enhance_warc.warc_revisit_enabled({'warc_revisit': '0'}))
        self.assertFalse(enhance_warc.warc_revisit_enabled({}))


if __name__ == '__main__':
    unittest.main()
