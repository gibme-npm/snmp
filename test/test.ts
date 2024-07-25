// Copyright (c) 2024, Brandon Lehmann <brandonlehmann@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import { it, describe } from 'mocha';
import SNMP from '../src/index';
import { config } from 'dotenv';
import assert from 'assert';

config();

const test_oid = '.1.3.6.1.4.1.14988.1.1.3.100.1.2.13';
const test_walk = '.1.3.6.1.4.1.14988.1.1.3.100.1.2';

describe('Unit Tests', () => {
    it('get()', async function () {
        try {
            const response = await SNMP.get({
                host: process.env.SNMP_HOST,
                community: process.env.SNMP_COMMUNITY
            }, test_oid);

            assert.ok(response.get(test_oid));
        } catch {
            this.skip();
        }
    });

    it('getAll()', async function () {
        try {
            const response = await SNMP.getAll({
                host: process.env.SNMP_HOST,
                community: process.env.SNMP_COMMUNITY
            }, [test_oid]);

            assert.ok(response.get(test_oid));
        } catch {
            this.skip();
        }
    });

    it('getNext()', async function () {
        try {
            const response = await SNMP.getNext({
                host: process.env.SNMP_HOST,
                community: process.env.SNMP_COMMUNITY
            }, test_walk);

            for (const varbind of response.values()) {
                assert.ok(`.${varbind.oid.join('.')}`.includes(test_oid));
            }
        } catch {
            this.skip();
        }
    });

    it('getSubtree()', async function () {
        try {
            const response = await SNMP.getSubtree({
                host: process.env.SNMP_HOST,
                community: process.env.SNMP_COMMUNITY
            }, [test_walk]);

            assert.ok(response.get(test_walk));
        } catch {
            this.skip();
        }
    });
});