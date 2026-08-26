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
	console.error('usage: generate_automated_assertion_index.mjs --release VERSION --source SHA (--output FILE | --check FILE)');
	process.exit(64);
}

function calleeName(node) {
	if (node?.type === 'Identifier') {
		return node.name;
	}
	if (node?.type === 'MemberExpression' && node.object?.type === 'Identifier') {
		return node.object.name;
	}
	return undefined;
}

function literalTitle(node) {
	return node?.type === 'Literal' && typeof node.value === 'string' ? node.value : undefined;
}

function collectAssertions(relativeFile) {
	const source = fs.readFileSync(path.join(repositoryRoot, relativeFile), 'utf8');
	const syntaxTree = espree.parse(source, {
		ecmaVersion: 'latest',
		loc: true,
		sourceType: 'script'
	});
	const assertions = [];

	function visit(node, describeStack) {
		if (!node || typeof node !== 'object') {
			return;
		}

		if (node.type === 'CallExpression') {
			const name = calleeName(node.callee);
			const title = literalTitle(node.arguments[0]);
			if ((name === 'test' || name === 'it') && title) {
				assertions.push({
					line: node.loc.start.line,
					title: [...describeStack, title].join(' › ')
				});
				return;
			}
			if (name === 'describe' && title) {
				const callback = node.arguments[1];
				if (callback?.body) {
					visit(callback.body, [...describeStack, title]);
				}
				return;
			}
		}

		for (const [name, child] of Object.entries(node)) {
			if (name === 'loc' || name === 'range') {
				continue;
			}
			if (Array.isArray(child)) {
				for (const entry of child) {
					visit(entry, describeStack);
				}
			} else if (child && typeof child === 'object' && child.type) {
				visit(child, describeStack);
			}
		}
	}

	visit(syntaxTree, []);
	return assertions.sort((left, right) => left.line - right.line);
}

function escapeCell(value) {
	return String(value).replaceAll('|', '\\|').replaceAll('\n', ' ').replaceAll('`', '\\`');
}

const testsRoot = path.join(repositoryRoot, 'tests');
const testFiles = [];
function findTests(directory) {
	for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
		const absolutePath = path.join(directory, entry.name);
		if (entry.isDirectory()) {
			findTests(absolutePath);
		} else if (entry.name.endsWith('.js')) {
			testFiles.push(path.relative(repositoryRoot, absolutePath));
		}
	}
}
findTests(testsRoot);
testFiles.sort();

const assertionsByFile = new Map(testFiles.map((relativeFile) => [relativeFile, collectAssertions(relativeFile)]));
const assertionCount = [...assertionsByFile.values()].reduce((total, assertions) => total + assertions.length, 0);
const suiteCount = [...assertionsByFile.values()].filter((assertions) => assertions.length > 0).length;
const lines = [
	`# ImprovedTube ${release} automated assertion inventory`,
	'',
	`Generated from uploaded source commit \`${sourceCommit}\` by \`scripts/appstore/generate_automated_assertion_index.mjs\`.`,
	'',
	`Jest assertions indexed: **${assertionCount}** across **${suiteCount}** suites (${testFiles.length} JavaScript test sources scanned).`,
	'',
	'Canonical command: `npm test -- --runInBand`.',
	''
];

let assertionNumber = 0;
for (const relativeFile of testFiles) {
	const assertions = assertionsByFile.get(relativeFile);
	if (assertions.length === 0) {
		continue;
	}
	lines.push(`## ${relativeFile} (${assertions.length})`, '');
	lines.push('| ID | Assertion | Source |');
	lines.push('| --- | --- | --- |');
	for (const assertion of assertions) {
		assertionNumber += 1;
		const id = `AUT-${String(assertionNumber).padStart(3, '0')}`;
		const source = `../../${relativeFile}#L${assertion.line}`;
		lines.push(`| ${id} | ${escapeCell(assertion.title)} | [${relativeFile}:${assertion.line}](${source}) |`);
	}
	lines.push('');
}

const rendered = `${lines.join('\n')}\n`;
const target = path.resolve(repositoryRoot, outputArgument || checkArgument);

if (checkArgument) {
	if (!fs.existsSync(target) || fs.readFileSync(target, 'utf8') !== rendered) {
		console.error(`automated assertion inventory is stale: ${path.relative(repositoryRoot, target)}`);
		process.exit(1);
	}
	console.log(`Automated assertion inventory is current: ${assertionCount} assertions`);
} else {
	fs.mkdirSync(path.dirname(target), {recursive: true});
	fs.writeFileSync(target, rendered);
	console.log(`Wrote ${path.relative(repositoryRoot, target)} with ${assertionCount} assertions`);
}
