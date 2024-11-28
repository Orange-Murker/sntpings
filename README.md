# SNTPings Pinger

This uses [Packet MMAP](https://www.kernel.org/doc/html/latest/networking/packet_mmap.html) to speed things up.

### Image Requirements

Use an 8-bit RGBA colour PNG image.

To use this code without modification, it is required for the image to fit perfectly into the ringbuffer because the image data is only copied to it once to increase performance.

On my machine the maximum block size is 8388608 bytes (can be different on yours).

So the image's `width * height * 512(frame size)` has to be a multiple of the maximum block size:  `(256 * 256 * 512) / 8388608 = 4`.

The frame size can be adjusted to your liking as long as the entire ping packet still fits into it.

### Usage

Place a suitable image at `sntpings/image.png`

```
mkdir build
cd build
cmake ..
make
sudo ./sntpings
```
