// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	// Canonical site URL. Served from a custom apex domain, so no `base` prefix.
	site: 'https://truthtable.dev',
	integrations: [
		starlight({
			title: 'TruthTable',
			description:
				'TruthTable is a verifiable query engine: it produces succinct cryptographic proofs that SQL query results are correct.',
			social: [
				{
					icon: 'github',
					label: 'GitHub',
					href: 'https://github.com/arkworks-rs/truth-table',
				},
			],
			sidebar: [
				{
					label: 'Getting Started',
					items: [
						{ label: 'Introduction', slug: 'guides/introduction' },
						{ label: 'Installation', slug: 'guides/installation' },
						{ label: 'Quick Start', slug: 'guides/quick-start' },
					],
				},
				{
					label: 'Concepts',
					items: [{ autogenerate: { directory: 'concepts' } }],
				},
				{
					label: 'Reference',
					items: [{ autogenerate: { directory: 'reference' } }],
				},
			],
		}),
	],
});
