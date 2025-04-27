// Package imports
import * as fs from 'fs';

export const safeFileExists = (filePath: string) => {
    try {
      fs.accessSync(filePath, fs.constants.F_OK);
      return true;
    } catch (error) {
      return false;
    }
}
 