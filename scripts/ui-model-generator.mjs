import { writeGenerated } from './ui-model-tools.mjs';

const generated = await writeGenerated(process.cwd());
if (generated.errors.length > 0) {
  console.error('Cannot generate UI model views from an invalid source:');
  for (const error of generated.errors) console.error(`- ${error}`);
  process.exitCode = 1;
} else {
  console.log('Generated Canonical UI Interaction Model Markdown and Mermaid views.');
}
