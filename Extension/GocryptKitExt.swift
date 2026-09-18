import Foundation
import FSKit

@main
struct GocryptKitExt: UnaryFileSystemExtension {
    typealias FileSystem = FSUnaryFileSystem & FSUnaryFileSystemOperations

    var fileSystem: FSUnaryFileSystem & FSUnaryFileSystemOperations {
        GocryptfsFileSystem()
    }
}
