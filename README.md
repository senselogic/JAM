![](https://github.com/senselogic/JAM/blob/master/LOGO/jam.png)

# Jam

File jammer.

## Installation

Install the [DMD 2 compiler](https://dlang.org/download.html) (using the MinGW setup option on Windows).

Build the executable with the following command line :

```bash
dmd -m64 jam.d
```

## Command line

```bash
jam `<option>`
```

### Options

```
--encrypt `<key>` `<nonce>` `<folder path>` `<filter>` [`<filter>` ...] : encrypt "🔓 ... 🔓" sections in matching files
--decrypt `<key>` `<nonce>` `<folder path>` `<filter>` [`<filter>` ...] : decrypt "🔒 ... 🔒" sections in matching files
```

### Examples

```bash
jam --encrypt "the-key" "the-nonce" FOLDER/ *.txt
```

```bash
jam --decrypt "the-key" "the-nonce" FOLDER/ *.txt
```

## Version

1.0

## Author

Eric Pelzer (ecstatic.coder@gmail.com).

## License

This project is licensed under the GNU General Public License version 3.

See the [LICENSE.md](LICENSE.md) file for details.
