// Copyright (c) 2024-2025, Brandon Lehmann <brandonlehmann@gmail.com>
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

import snmp, { VarBind as SNMPVarBind } from 'snmp-native';

export class SNMP {
    private readonly _session = new snmp.Session();

    private static _session?: snmp.Session;

    private static get session (): snmp.Session {
        this._session ??= new snmp.Session();

        return this._session;
    }

    private get session (): snmp.Session {
        return this._session;
    }

    /**
     * Closes the underlying SNMP session
     */
    public static close () {
        return this.session?.close();
    }

    /**
     * Performs a fetch of all requested values
     * @deprecated
     * @param options
     * @param oids
     */
    public static async fetch (options: SNMP.Options, oids: SNMP.OID[]): Promise<SNMP.Response<SNMP.VarBind>> {
        return this.getAll(options, oids);
    }

    /**
     * Perform a simple GetRequest
     * @param options
     * @param oid
     */
    public static async get (
        options: SNMP.Options,
        oid: SNMP.OID
    ): Promise<SNMP.Response<SNMP.VarBind>> {
        return SNMP._get(this.session, options, oid);
    }

    /**
     * Perform repeated GetRequests to fetch all the required values.
     * Multiple OIDs will get packed into as few GetRequest packets as possible to
     * minimize round trip delays.
     *
     * Gets will be issued serially (not in parallel) to avoid flooding hosts.
     * @param options
     * @param oids
     */
    public static async getAll (options: SNMP.Options, oids: SNMP.OID[]): Promise<SNMP.Response<SNMP.VarBind>> {
        return SNMP._getAll(this.session, options, oids);
    }

    /**
     * Perform a simple GetNextRequest
     * @param options
     * @param oid
     */
    public static async getNext (
        options: SNMP.Options,
        oid: SNMP.OID
    ): Promise<SNMP.Response<SNMP.VarBind>> {
        return SNMP._getNext(this.session, options, oid);
    }

    /**
     * Perform repeated GetNextRequests to fetch all values in the specified tree
     *
     * Note: This is equivalent to a 'walk'
     * @param options
     * @param oids
     */
    public static async getSubtree (options: SNMP.Options, oids: SNMP.OID[]): Promise<SNMP.Response<SNMP.VarBind[]>> {
        return SNMP._getSubtree(this.session, options, oids);
    }

    /**
     * Perform a simple SetRequest
     * @param options
     * @param oid
     * @param type
     * @param value
     */
    public static async set (
        options: SNMP.Options,
        oid: SNMP.OID,
        type?: SNMP.DataType,
        value?: any
    ): Promise<SNMP.Response<SNMP.VarBind>> {
        return SNMP._set(this.session, options, oid, type, value);
    }

    /**
     * Performs a walk of the supplied SNMP oids
     * @deprecated
     * @param options
     * @param oids
     */
    public static async walk (options: SNMP.Options, oids: SNMP.OID[]): Promise<SNMP.Response<SNMP.VarBind[]>> {
        return this.getSubtree(options, oids);
    }

    private static async _get (
        session: snmp.Session,
        options: SNMP.Options,
        oid: SNMP.OID
    ): Promise<SNMP.Response<SNMP.VarBind>> {
        return new Promise((resolve, reject) => {
            const result: SNMP.Response<SNMP.VarBind> = {};

            session.get({ oid, ...options }, (error, varbinds) => {
                if (error) {
                    return reject(new Error(error.toString()));
                }

                for (let i = 0; i < varbinds.length; ++i) {
                    const varbind = varbinds[i];

                    const oid: SNMP.OID = `.${varbind.oid.join('.')}`;

                    result[oid] = {
                        ...varbind,
                        oid
                    };
                }

                return resolve(result);
            });
        });
    }

    private static async _getAll (
        session: snmp.Session,
        options: SNMP.Options,
        oids: SNMP.OID[]
    ): Promise<SNMP.Response<SNMP.VarBind>> {
        return new Promise((resolve, reject) => {
            const result: SNMP.Response<SNMP.VarBind> = {};

            if (oids.length === 0) return resolve(result);

            session.getAll({ oids, ...options }, (error, varbinds) => {
                if (error) {
                    return reject(new Error(error.toString()));
                }

                for (let i = 0; i < varbinds.length; ++i) {
                    const varbind = varbinds[i];

                    const oid: SNMP.OID = `.${varbind.oid.join('.')}`;

                    result[oid] = {
                        ...varbind,
                        oid
                    };
                }

                return resolve(result);
            });
        });
    }

    private static async _getNext (
        session: snmp.Session,
        options: SNMP.Options,
        oid: SNMP.OID
    ): Promise<SNMP.Response<SNMP.VarBind>> {
        return new Promise((resolve, reject) => {
            const result: SNMP.Response<SNMP.VarBind> = {};

            session.getNext({ oid, ...options }, (error, varbinds) => {
                if (error) {
                    return reject(new Error(error.toString()));
                }

                for (let i = 0; i < varbinds.length; ++i) {
                    const varbind = varbinds[i];

                    const oid: SNMP.OID = `.${varbind.oid.join('.')}`;
                    result[oid] = {
                        ...varbind,
                        oid
                    };
                }

                return resolve(result);
            });
        });
    }

    private static async _getSubtree (
        session: snmp.Session,
        options: SNMP.Options,
        oids: SNMP.OID[]
    ): Promise<SNMP.Response<SNMP.VarBind[]>> {
        const result: SNMP.Response<SNMP.VarBind[]> = {};

        if (oids.length === 0) {
            return result;
        }

        const run = async (oid: SNMP.OID): Promise<[SNMP.OID, SNMP.VarBind[]]> => new Promise((resolve, reject) => {
            session.getSubtree({ oid, ...options }, (error, varbinds) => {
                if (error) {
                    return reject(new Error(error.toString()));
                }

                return resolve([oid, varbinds.map(varbind => {
                    const oid: SNMP.OID = `.${varbind.oid.join('.')}`;

                    return {
                        ...varbind,
                        oid
                    };
                })]);
            });
        });

        const responses = await Promise.all(oids.map(oid => run(oid)));

        for (let i = 0; i < responses.length; ++i) {
            const [oid, varbinds] = responses[i];

            result[oid] = varbinds;
        }

        return result;
    }

    private static async _set (
        session: snmp.Session,
        options: SNMP.Options,
        oid: SNMP.OID,
        type?: SNMP.DataType,
        value?: any
    ): Promise<SNMP.Response<SNMP.VarBind>> {
        return new Promise((resolve, reject) => {
            const result: SNMP.Response<SNMP.VarBind> = {};

            session.set({ oid, type, value, ...options }, (error, varbinds) => {
                if (error) {
                    return reject(new Error(error.toString()));
                }

                for (let i = 0; i < varbinds.length; ++i) {
                    const varbind = varbinds[i];

                    const oid: SNMP.OID = `.${varbind.oid.join('.')}`;

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
     * Closes the underlying SNMP Session
     */
    public close () {
        return this.session.close();
    }

    /**
     * Performs a fetch of all requested values
     * @param options
     * @param oids
     * @deprecated
     */
    public async fetch (options: SNMP.Options, oids: SNMP.OID[]): Promise<SNMP.Response<SNMP.VarBind>> {
        return this.getAll(options, oids);
    }

    /**
     * Perform a simple GetRequest
     * @param options
     * @param oid
     */
    public async get (options: SNMP.Options, oid: SNMP.OID): Promise<SNMP.Response<SNMP.VarBind>> {
        return SNMP._get(this.session, options, oid);
    }

    /**
     * Perform repeated GetRequests to fetch all the required values.
     * Multiple OIDs will get packed into as few GetRequest packets as possible to
     * minimize round trip delays.
     *
     * Gets will be issued serially (not in parallel) to avoid flooding hosts.
     * @param options
     * @param oids
     */
    public async getAll (options: SNMP.Options, oids: SNMP.OID[]): Promise<SNMP.Response<SNMP.VarBind>> {
        return SNMP._getAll(this.session, options, oids);
    }

    /**
     * Perform a simple GetNextRequest
     * @param options
     * @param oid
     */
    public async getNext (options: SNMP.Options, oid: SNMP.OID): Promise<SNMP.Response<SNMP.VarBind>> {
        return SNMP._getNext(this.session, options, oid);
    }

    /**
     * Perform repeated GetNextRequests to fetch all values in the specified tree
     *
     * Note: This is equivalent to a 'walk'
     * @param options
     * @param oids
     */
    public async getSubtree (options: SNMP.Options, oids: SNMP.OID[]): Promise<SNMP.Response<SNMP.VarBind[]>> {
        return SNMP._getSubtree(this.session, options, oids);
    }

    /**
     * Perform a simple SetRequest
     * @param options
     * @param oid
     * @param type
     * @param value
     */
    public async set (
        options: SNMP.Options,
        oid: SNMP.OID,
        type?: SNMP.DataType,
        value?: any
    ): Promise<SNMP.Response<SNMP.VarBind>> {
        return SNMP._set(this.session, options, oid, type, value);
    }

    /**
     * Performs a walk of the supplied SNMP oids
     * @deprecated
     * @param options
     * @param oids
     */
    public async walk (options: SNMP.Options, oids: SNMP.OID[]): Promise<SNMP.Response<SNMP.VarBind[]>> {
        return this.getSubtree(options, oids);
    }
}

export namespace SNMP {
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

    export type Options = snmp.SessionOptions;

    export type OID = `.${string}`;

    export type VarBind = Omit<SNMPVarBind, 'oid'> & {
        oid: OID;
    }

    export type Response<Type> = Record<OID, Type | undefined>;
}

export default SNMP;
