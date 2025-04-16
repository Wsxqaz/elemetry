# elemetry

elemetry is a toolkit for tracking and enumerating Windows kernel callbacks, designed for security research and analysis of kernel-mode activities.

> NOTE: this project is a WIP

## Project Structure

This repository consists of several interconnected components:

### [elemetryDriver](./elemetryDriver)

The kernel-mode driver component that enables access to kernel-level information. This driver:
- Tracks and enumerates various kernel callbacks
- Allows user-mode applications to query kernel structures
- Acts as a bridge between the Windows kernel and user-mode applications

### [elemetryClient](./elemetryClient)

A user-mode application that communicates with the elemetryDriver to:
- Enumerate loaded kernel modules
- Display information about kernel callbacks (Load Image, Process Creation)
- Provide symbol resolution through Microsoft Symbol Server
- Present a user interface for interacting with the kernel data

### [testDriver](./testDriver)

A testing driver used for development and verification purposes:
- Implements sample callbacks that can be detected by elemetryDriver
- Serves as a reference implementation for callback mechanisms
- Useful for testing the detection capabilities of the main components

## Getting Started

Each component has its own README with specific build and usage instructions:
- For the driver component, see [elemetryDriver/README.md](./elemetryDriver/README.md)
- For the client application, see [elemetryClient/README.md](./elemetryClient/README.md)

## Usage Warning

This project is intended for educational and research purposes in controlled environments. The drivers require special permissions and test-signing modes to run on modern Windows systems.

## TODO

- [ ] Windows Form based interface
- [ ] Callback suppression

## References

- [TelemetrySourcerer](https://github.com/jthuraisamy/TelemetrySourcerer)

## Credits

- Shoutout to [@jgajek](https://github.com/jgajek) for the original idea