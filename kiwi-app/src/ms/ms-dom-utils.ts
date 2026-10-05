/* Ported from Mailspring `app/src/dom-utils.ts` — verbatim subset. */
export const DOMUtils = {
  scrollAdjustmentToMakeNodeVisibleInContainer(node: Element, container: Element) {
    if (!node) {
      return;
    }
    const nodeRect = node.getBoundingClientRect();
    const containerRect = container.getBoundingClientRect();
    return this.scrollAdjustmentToMakeRectVisibleInRect(nodeRect, containerRect);
  },

  scrollAdjustmentToMakeRectVisibleInRect(nodeRect: DOMRect, containerRect: DOMRect) {
    const distanceBelowBottom =
      nodeRect.top + nodeRect.height - (containerRect.top + containerRect.height);
    if (distanceBelowBottom >= 0) {
      return distanceBelowBottom;
    }

    const distanceAboveTop = containerRect.top - nodeRect.top;
    if (distanceAboveTop >= 0) {
      return -distanceAboveTop;
    }

    return 0;
  },
};
