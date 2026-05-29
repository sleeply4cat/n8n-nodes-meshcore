import type { Icon, ICredentialType, INodeProperties } from 'n8n-workflow';

export class MeshCoreTcpApi implements ICredentialType {
	name = 'meshCoreTcpApi';

	displayName = 'MeshCore TCP API';

	icon: Icon = { light: 'file:../icons/meshcore.svg', dark: 'file:../icons/meshcore.dark.svg' };

	documentationUrl = 'https://github.com/meshcore-dev/MeshCore';

	properties: INodeProperties[] = [
		{
			displayName: 'Host',
			name: 'host',
			type: 'string',
			default: '',
			required: true,
			placeholder: '10.1.0.226',
			description: 'IP address or hostname of the MeshCore WiFi companion device',
		},
		{
			displayName: 'Port',
			name: 'port',
			type: 'number',
			default: 5000,
			required: true,
			description: 'TCP port the companion_radio_wifi firmware listens on',
		},
		{
			displayName: 'Device PIN',
			name: 'devicePin',
			type: 'number',
			typeOptions: { password: true },
			default: undefined,
			description:
				'Optional connection PIN, only if the firmware enforces one over TCP. Leave empty if unsure.',
		},
	];
}
