/** Serializes asynchronous read-modify-write operations and recovers after failures. */
export class SerializedMutationQueue {
  constructor() {
    this.tail = Promise.resolve();
  }

  run(operation) {
    const result = this.tail.then(operation, operation);
    this.tail = result.then(() => undefined, () => undefined);
    return result;
  }
}
