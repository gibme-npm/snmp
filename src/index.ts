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

import snmp, { SessionOptions, OID, VarBind } from 'snmp-native';

export default abstract class SNMP {
    /**
     * Attempts to fetch the SNMP OID information using the specified options and OIDs
     *
     * @param options
     * @param oids
     */
    public static async fetch (options: SessionOptions, oids: OID[]): Promise<Map<OID, VarBind>> {
        return new Promise((resolve, reject) => {
            if (oids.length === 0) {
                return resolve(new Map<OID, VarBind>());
            }

            const session = new snmp.Session(options);

            const result = new Map<OID, VarBind>();

            session.getAll({ oids }, (error, varbinds) => {
                session.close();

                if (error) {
                    return reject(new Error(error.toString()));
                }

                for (const varbind of varbinds) {
                    result.set(`.${varbind.oid.join('.')}`, varbind);
                }

                return resolve(result);
            });
        });
    }

    /**
     * Attempts to 'walk' the specified SNMP OIDs using the specified options and OIDs
     *
     * @param options
     * @param oids
     */
    public static async walk (options: SessionOptions, oids: OID[]): Promise<Map<OID, VarBind[]>> {
        if (oids.length === 0) {
            return new Map<OID, VarBind[]>();
        }

        const session = new snmp.Session(options);

        const result = new Map<OID, VarBind[]>();

        const run = async (oid: OID): Promise<[OID, VarBind[]]> => new Promise((resolve, reject) => {
            session.getSubtree({ oid }, (error, varbinds) => {
                if (error) {
                    return reject(new Error(error.toString()));
                }

                return resolve([oid, varbinds]);
            });
        });

        const responses = await Promise.all(oids.map(oid => run(oid)));

        session.close();

        for (const [oid, varbinds] of responses) {
            result.set(oid, varbinds);
        }

        return result;
    }
}
