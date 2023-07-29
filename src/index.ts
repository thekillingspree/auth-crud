import dotenv from 'dotenv';
dotenv.config();
import { checkEnvVariables } from './utils';

checkEnvVariables();

import initServer from './app';

void initServer();
