#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';

const require = createRequire(import.meta.url);
const espree = require('espree');
const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, '../..');

const argumentsByName = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
	argumentsByName.set(process.argv[index], process.argv[index + 1]);
}

const release = argumentsByName.get('--release');
const sourceCommit = argumentsByName.get('--source');
const outputArgument = argumentsByName.get('--output');
const checkArgument = argumentsByName.get('--check');

if (!release || !sourceCommit || (!outputArgument && !checkArgument) || (outputArgument && checkArgument)) {
	console.error('usage: generate_feature_index.mjs --release VERSION --source SHA (--output FILE | --check FILE)');
	process.exit(64);
}

const interactiveComponents = new Set([
	'button',
	'checkbox',
	'color-picker',
	'countComponent',
	'input',
	'radio',
	'select',
	'shortcut',
	'slider',
	'switch',
	'text-field',
	'time'
]);

const componentProfiles = {
	button: 'UI-A',
	checkbox: 'UI-C',
	'color-picker': 'UI-O',
	countComponent: 'UI-V',
	input: 'UI-V',
	radio: 'UI-C',
	select: 'UI-C',
	shortcut: 'UI-K',
	slider: 'UI-V',
	switch: 'UI-S',
	'text-field': 'UI-V',
	time: 'UI-V'
};

const categories = {
	'menu/skeleton.js': ['Menu shell', 'MNU'],
	'menu/skeleton-parts/active-features.js': ['Active features', 'ACT'],
	'menu/skeleton-parts/analyzer.js': ['Analyzer', 'ANL'],
	'menu/skeleton-parts/appearance.js': ['Appearance', 'APP'],
	'menu/skeleton-parts/blocklist.js': ['Blocklist', 'BLK'],
	'menu/skeleton-parts/channel.js': ['Channel', 'CHN'],
	'menu/skeleton-parts/dark-light-switch.js': ['Dark/light switch', 'DRK'],
	'menu/skeleton-parts/general.js': ['General', 'GEN'],
	'menu/skeleton-parts/mixer.js': ['Mixer', 'MIX'],
	'menu/skeleton-parts/night-mode.js': ['Night mode', 'NGT'],
	'menu/skeleton-parts/player.js': ['Player', 'PLY'],
	'menu/skeleton-parts/playlist.js': ['Playlist', 'PLS'],
	'menu/skeleton-parts/search.js': ['Menu search', 'SRC'],
	'menu/skeleton-parts/settings.js': ['Settings and data', 'SET'],
	'menu/skeleton-parts/shortcuts.js': ['Shortcuts', 'KEY'],
	'menu/skeleton-parts/themes.js': ['Themes', 'THM']
};

function propertyName(node) {
	return node?.name ?? node?.value ?? '';
}

function property(objectExpression, name) {
	return objectExpression.properties?.find((candidate) =>
		candidate.type === 'Property' && propertyName(candidate.key) === name
	);
}

function literalValue(candidate) {
	return candidate?.value?.type === 'Literal' ? candidate.value.value : undefined;
}

function nestedLabel(objectExpression) {
	const label = property(objectExpression, 'label');
	if (label?.value?.type !== 'ObjectExpression') {
		return undefined;
	}

	return literalValue(property(label.value, 'text'));
}

function controlKey(parent, objectExpression) {
	if (parent?.type === 'Property') {
		return propertyName(parent.key);
	}
	if (parent?.type === 'AssignmentExpression' && parent.left.type === 'MemberExpression') {
		return propertyName(parent.left.property);
	}
	if (parent?.type === 'VariableDeclarator') {
		return propertyName(parent.id);
	}

	return literalValue(property(objectExpression, 'text'))
		|| literalValue(property(objectExpression, 'title'))
		|| 'anonymous-control';
}

function defaultValue(objectExpression) {
	const value = literalValue(property(objectExpression, 'value'));
	if (value === undefined) {
		return 'implicit';
	}

	return JSON.stringify(value);
}

function optionCount(objectExpression) {
	const options = property(objectExpression, 'options');
	if (options?.value?.type !== 'ArrayExpression') {
		return '—';
	}

	return String(options.value.elements.length);
}

function escapeCell(value) {
	return String(value ?? '')
		.replaceAll('|', '\\|')
		.replaceAll('\n', ' ')
		.replaceAll('`', '\\`');
}

function collectControls(relativeFile) {
	const source = fs.readFileSync(path.join(repositoryRoot, relativeFile), 'utf8');
	const syntaxTree = espree.parse(source, {
		ecmaVersion: 'latest',
		loc: true,
		sourceType: 'script'
	});
	const controls = [];

	function visit(node, parent) {
		if (!node || typeof node !== 'object') {
			return;
		}

		if (node.type === 'ObjectExpression') {
			const component = literalValue(property(node, 'component'));
			if (interactiveComponents.has(component)) {
				const key = controlKey(parent, node);
				const label = literalValue(property(node, 'text'))
					|| literalValue(property(node, 'title'))
					|| nestedLabel(node)
					|| key;
				const explicitStorage = literalValue(property(node, 'storage'));
				const radio = property(node, 'radio');
				const radioGroup = radio?.value?.type === 'ObjectExpression'
					? literalValue(property(radio.value, 'group'))
					: undefined;
				const storage = component === 'button'
					? '—'
					: explicitStorage || radioGroup || key;

				controls.push({
					component,
					default: defaultValue(node),
					key,
					label,
					line: node.loc.start.line,
					options: optionCount(node),
					profile: componentProfiles[component],
					storage
				});
			}
		}

		for (const [name, child] of Object.entries(node)) {
			if (name === 'loc' || name === 'range') {
				continue;
			}
			if (Array.isArray(child)) {
				for (const entry of child) {
					visit(entry, node);
				}
			} else if (child && typeof child === 'object' && child.type) {
				visit(child, node);
			}
		}
	}

	visit(syntaxTree, undefined);
	return controls.sort((left, right) => left.line - right.line || left.key.localeCompare(right.key));
}

const files = Object.keys(categories).filter((relativeFile) =>
	fs.existsSync(path.join(repositoryRoot, relativeFile))
);
const controlsByFile = new Map(files.map((relativeFile) => [relativeFile, collectControls(relativeFile)]));
const allControls = [...controlsByFile.values()].flat();
const countsByComponent = new Map();
for (const control of allControls) {
	countsByComponent.set(control.component, (countsByComponent.get(control.component) || 0) + 1);
}

const lines = [
	`# ImprovedTube ${release} feature inventory`,
	'',
	`Generated from uploaded source commit \`${sourceCommit}\` by \`scripts/appstore/generate_feature_index.mjs\`.`,
	'Every row inherits the assertion profile shown in the **Assertions** column; the profiles are defined in the companion pre-publication test index.',
	'',
	`Total interactive controls: **${allControls.length}** across **${files.length}** source surfaces.`,
	'',
	'## Component totals',
	'',
	'| Component | Count | Assertion profile |',
	'| --- | ---: | --- |'
];

for (const [component, count] of [...countsByComponent.entries()].sort()) {
	lines.push(`| ${component} | ${count} | ${componentProfiles[component]} |`);
}

for (const relativeFile of files) {
	const [categoryName, prefix] = categories[relativeFile];
	const controls = controlsByFile.get(relativeFile);
	lines.push('', `## ${categoryName} (${controls.length})`, '');
	lines.push('| ID | Feature/control | Key | Type | Storage/group | Default | Options | Assertions | Source |');
	lines.push('| --- | --- | --- | --- | --- | --- | ---: | --- | --- |');
	controls.forEach((control, index) => {
		const id = `${prefix}-${String(index + 1).padStart(3, '0')}`;
		const source = `../../${relativeFile}#L${control.line}`;
		lines.push(`| ${id} | ${escapeCell(control.label)} | \`${escapeCell(control.key)}\` | ${control.component} | \`${escapeCell(control.storage)}\` | ${escapeCell(control.default)} | ${control.options} | ${control.profile} | [${relativeFile}:${control.line}](${source}) |`);
	});
}

lines.push('');
const rendered = `${lines.join('\n')}\n`;
const target = path.resolve(repositoryRoot, outputArgument || checkArgument);

if (checkArgument) {
	if (!fs.existsSync(target) || fs.readFileSync(target, 'utf8') !== rendered) {
		console.error(`feature inventory is stale: ${path.relative(repositoryRoot, target)}`);
		process.exit(1);
	}
	console.log(`Feature inventory is current: ${allControls.length} controls`);
} else {
	fs.mkdirSync(path.dirname(target), {recursive: true});
	fs.writeFileSync(target, rendered);
	console.log(`Wrote ${path.relative(repositoryRoot, target)} with ${allControls.length} controls`);
}
