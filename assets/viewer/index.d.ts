import type { MountViewerOptions, ViewerHandle } from "./types.js";
export type { MountViewerOptions, ViewerHandle, ViewerNodeInfo, ViewerOptions } from "./types.js";
/** Mount one read-only canvas. Use the HTML component for multiple isolated diagrams. */
export declare function mountViewer(container: Element, options: MountViewerOptions): ViewerHandle;
