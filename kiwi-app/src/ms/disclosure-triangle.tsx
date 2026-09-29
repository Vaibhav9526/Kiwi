/* Ported from Mailspring `app/src/components/disclosure-triangle.tsx` —
 * verbatim; `label` dropped from the render destructure only (never read,
 * strict noUnusedLocals). */
import React from 'react';

type DisclosureTriangleProps = {
  collapsed?: boolean;
  visible?: boolean;
  onCollapseToggled?: (...args: any[]) => any;
  label?: string;
};

export class DisclosureTriangle extends React.Component<DisclosureTriangleProps> {
  static displayName = 'DisclosureTriangle';

  static defaultProps = { onCollapseToggled() {} };

  render() {
    const { visible, collapsed, onCollapseToggled } = this.props;
    let classnames = 'disclosure-triangle';
    if (visible) {
      classnames += ' visible';
    }
    if (collapsed) {
      classnames += ' collapsed';
    }
    return (
      <div className={classnames} aria-hidden="true" onClick={onCollapseToggled}>
        <div />
      </div>
    );
  }
}
