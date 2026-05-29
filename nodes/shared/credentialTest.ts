import type {
	ICredentialsDecrypted,
	ICredentialTestFunctions,
	INodeCredentialTestResult,
} from 'n8n-workflow';

import { ConnectionManager } from './ConnectionManager';

/**
 * Credential test shared by both MeshCore nodes. Verifies reachability by opening a
 * short-lived shared TCP connection and releasing it. If a node is already connected
 * to this device, the shared connection is reused (ref-counted) and left untouched.
 */
export async function meshCoreTcpApiTest(
	this: ICredentialTestFunctions,
	credential: ICredentialsDecrypted,
): Promise<INodeCredentialTestResult> {
	const data = credential.data ?? {};
	const host = (data.host as string)?.trim();
	const port = Number(data.port) || 5000;

	if (!host) {
		return { status: 'Error', message: 'Host is required' };
	}

	try {
		const connection = await ConnectionManager.acquire({ host, port, connectTimeoutMs: 8000 });
		ConnectionManager.release(connection);
		return { status: 'OK', message: `Connected to MeshCore device at ${host}:${port}` };
	} catch (error) {
		return { status: 'Error', message: (error as Error).message };
	}
}
