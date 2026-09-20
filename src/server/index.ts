import {createApp} from './api';
import {fileURLToPath} from 'node:url';

const app = createApp();

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 4174);
  app.listen(port, '127.0.0.1', () => console.log(`cert path workbench http://127.0.0.1:${port}`));
}

export {app};
