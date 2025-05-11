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
 

const codenamesMap: {[versionNumber: string]: string} = {
  '1.0': 'Apple Pie',
  '1.1': 'Banana Bread',
  '1.5': 'Cupcake',
  '1.6': 'Donut',
  '2.0': 'Eclair',
  '2.0.1': 'Eclair',
  '2.1': 'Eclair',
  '2.2': 'Froyo',
  '2.2.3': 'Froyo',
  '2.3': 'Gingerbread',
  '2.3.7': 'Gingerbread',
  '3.0': 'Honeycomb',
  '3.2.6': 'Honeycomb',
  '4.0': 'Ice Cream Sandwich',
  '4.0.4': 'Ice Cream Sandwich',
  '4.1': 'Jelly Bean',
  '4.2': 'Jelly Bean',
  '4.3': 'Jelly Bean',
  '4.4': 'KitKat',
  '5.0': 'Lollipop',
  '5.1': 'Lollipop',
  '6.0': 'Marshmallow',
  '7.0': 'Nougat',
  '7.1': 'Nougat',
  '8.0': 'Oreo',
  '8.1': 'Oreo',
  '9': 'Pie',
  '10': 'Quince Tart',
  '11': 'Red Velvet Cake',
  '12': 'Snow Cone',
  '12L': 'Snow Cone v2',
  '13': 'Tiramisu',
  '14': 'Upside Down Cake',
  '15': 'Vanilla Ice Cream',
  '16': 'Baklava'
}

export const versionNumberToCodename = (versionNumber: string): string => {
  // Try exact match
  if (codenamesMap[versionNumber]) return codenamesMap[versionNumber];

  // Try major version fallback (e.g., "4.2.2" -> "4.2")
  const majorMinor = versionNumber.split('.').slice(0, 2).join('.');
  if (codenamesMap[majorMinor]) return codenamesMap[majorMinor];

  const majorOnly = versionNumber.split('.')[0];
  if (codenamesMap[majorOnly]) return codenamesMap[majorOnly];

  return 'Unknown';
}