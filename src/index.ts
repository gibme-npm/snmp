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

import snmp, { SessionOptions, VarBind as SNMPVarBind } from 'snmp-native';

export { SessionOptions };

export enum DataType {
    Integer = 0x02,
    OctetString = 0x04,
    Null = 0x05,
    ObjectIdentifier = 0x06,
    Sequence = 0x30,
    IPAddress = 0x40,
    Counter = 0x41,
    Gauge = 0x42,
    TimeTicks = 0x43,
    Opaque = 0x44,
    NsapAddress = 0x45,
    Counter64 = 0x46,
    NoSuchObject = 0x80,
    NoSuchInstance = 0x81,
    EndOfMibView = 0x82,
    PDUBase = 0xA0
}

export enum Versions {
    SNMPv1 = 0,
    SNMPv2c = 1
}

export type OID = `.${string}`;

export interface VarBind extends Omit<SNMPVarBind, 'oid'> {
    oid: OID;
}

export type SNMPResult<Type> = Record<OID, Type>;

export default abstract class SNMP {
    private static session = new snmp.Session();

    /**
     * Closes the underlying SNMP session
     */
    public static close () {
        return this.session.close();
    }

    /**
     * Performs a fetch of all required values
     *
     * @deprecated
     * @param options
     * @param oids
     */
    public static async fetch (options: SessionOptions, oids: OID[]): Promise<SNMPResult<VarBind>> {
        return this.getAll(options, oids);
    }

    /**
     * Perform a simple GetRequest
     *
     * @param options
     * @param oid
     */
    public static async get (
        options: SessionOptions,
        oid: OID
    ): Promise<SNMPResult<VarBind>> {
        return new Promise((resolve, reject) => {
            const result: SNMPResult<VarBind> = {};

            this.session.get({ oid, ...options }, (error, varbinds) => {
                if (error) {
                    return reject(new Error(error.toString()));
                }

                for (const varbind of varbinds) {
                    const oid: OID = `.${varbind.oid.join('.')}`;

                    result[oid] = {
                        ...varbind,
                        oid
                    };
                }

                return resolve(result);
            });
        });
    }

    /**
     * Perform repeated GetRequests to fetch all the required values.
     * Multiple OIDs will get packed into as few GetRequest packets as possible to
     * minimize roundtrip delays.
     *
     * Gets will be issued serially (not in parallell) to avoid flooding hosts.
     *
     * @param options
     * @param oids
     */
    public static async getAll (
        options: SessionOptions,
        oids: OID[]
    ): Promise<SNMPResult<VarBind>> {
        return new Promise((resolve, reject) => {
            const result: SNMPResult<VarBind> = {};

            if (oids.length === 0) {
                return resolve(result);
            }

            this.session.getAll({ oids, ...options }, (error, varbinds) => {
                if (error) {
                    return reject(new Error(error.toString()));
                }

                for (const varbind of varbinds) {
                    const oid: OID = `.${varbind.oid.join('.')}`;

                    result[oid] = {
                        ...varbind,
                        oid
                    };
                }

                return resolve(result);
            });
        });
    }

    /**
     * Perform a simple GetNextRequest
     *
     * @param options
     * @param oid
     */
    public static async getNext (
        options: SessionOptions,
        oid: OID
    ): Promise<SNMPResult<VarBind>> {
        return new Promise((resolve, reject) => {
            const result: SNMPResult<VarBind> = {};

            this.session.getNext({ oid, ...options }, (error, varbinds) => {
                if (error) {
                    return reject(new Error(error.toString()));
                }

                for (const varbind of varbinds) {
                    const oid: OID = `.${varbind.oid.join('.')}`;
                    result[oid] = {
                        ...varbind,
                        oid
                    };
                }

                return resolve(result);
            });
        });
    }

    /**
     * Perform repeated GetNextRequests to fetch all values in the specified tree
     *
     * Note: This is equivalent to a 'walk'
     *
     * @param options
     * @param oids
     */
    public static async getSubtree (
        options: SessionOptions,
        oids: OID[]
    ): Promise<SNMPResult<VarBind[]>> {
        const result: SNMPResult<VarBind[]> = {};

        if (oids.length === 0) {
            return result;
        }

        const run = async (oid: OID): Promise<[OID, VarBind[]]> => new Promise((resolve, reject) => {
            this.session.getSubtree({ oid, ...options }, (error, varbinds) => {
                if (error) {
                    return reject(new Error(error.toString()));
                }

                return resolve([oid, varbinds.map(varbind => {
                    const oid: OID = `.${varbind.oid.join('.')}`;

                    return {
                        ...varbind,
                        oid
                    };
                })]);
            });
        });

        const responses = await Promise.all(oids.map(oid => run(oid)));

        for (const [oid, varbinds] of responses) {
            result[oid] = varbinds;
        }

        return result;
    }

    /**
     * Perform a simple SetRequest
     *
     * @param options
     * @param oid
     * @param type
     * @param value
     */
    public static async set (
        options: SessionOptions,
        oid: OID,
        type?: DataType,
        value?: any
    ): Promise<SNMPResult<VarBind>> {
        return new Promise((resolve, reject) => {
            const result: SNMPResult<VarBind> = {};

            this.session.set({ oid, type, value, ...options }, (error, varbinds) => {
                if (error) {
                    return reject(new Error(error.toString()));
                }

                for (const varbind of varbinds) {
                    const oid: OID = `.${varbind.oid.join('.')}`;

                    result[oid] = {
                        ...varbind,
                        oid
                    };
                }

                return resolve(result);
            });
        });
    }

    /**
     * Performs a walk of the supplied SNMP oids
     *
     * @deprecated
     * @param options
     * @param oids
     */
    public static async walk (options: SessionOptions, oids: OID[]): Promise<SNMPResult<VarBind[]>> {
        return this.getSubtree(options, oids);
    }
}
