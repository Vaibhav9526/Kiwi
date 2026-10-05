/* Ported from Mailspring `app/src/flux/models/utils.ts` — the subset the
 * component layer needs. `isEqual`/`_isEqual`/`isEqualReact`/`fastOmit`/
 * `generateTempId` are verbatim Mailspring code; `imageNamed` is adapted
 * (their icon cache resolves PNG assets — we map icon names in RetinaImg).
 */
import _ from "underscore";

const objToString = Object.prototype.toString;

export function fastOmit(props: Record<string, any>, without: string[]) {
  const otherProps = Object.assign({}, props);
  for (const w of without) {
    delete otherProps[w];
  }
  return otherProps;
}

export function generateTempId() {
  const s4 = () =>
    Math.floor((1 + Math.random()) * 0x10000)
      .toString(16)
      .substring(1);
  return `local-${s4()}${s4()}-${s4()}`;
}

/** Mailspring resolved PNG assets via a resource cache; KIWI icons are the
 *  `Icon` registry. The name passes through and the RetinaImg port maps it. */
export function imageNamed(fullname: string) {
  return fullname;
}

// Vendor verbatim: list plumbing used by ListTabular's range math and the
// thread-list columns' attachment-icon check.
export function range(left: number, right: number, inclusive = true) {
  const range = [];
  const ascending = left < right;
  const end = !inclusive ? right : ascending ? right + 1 : right - 1;
  for (let i = left; ascending ? i < end : i > end; ascending ? i++ : i--) {
    range.push(i);
  }
  return range;
}

export function showIconForAttachments(files: any[]) {
  if (!(files instanceof Array)) {
    return false;
  }
  // Attachment-icon rule: inline parts (contentId set) and files under 12 KiB
  // don't count — matching KIWI's own attachmentCount predicate.
  return files.find((f) => !f.contentId || f.size > 12 * 1024);
}

// This looks for and removes plus-ing, it taks a VERY liberal approach
// to match an email address. We'd rather let false positives through.
export function toEquivalentEmailForm(email: string) {
  // https://regex101.com/r/iS7kD5/3
  // eslint-disable-next-line
  const [, user, domain] = /^([^+]+).*@(.+)$/gi.exec(email) || [null, "", ""];
  return `${user}@${domain}`.trim().toLowerCase();
}

export function emailIsEquivalent(email1: string, email2: string) {
  if (email1 == null) {
    email1 = "";
  }
  if (email2 == null) {
    email2 = "";
  }
  email1 = email1.toLowerCase().trim();
  email2 = email2.toLowerCase().trim();
  if (email1 === email2) {
    return true;
  }
  email1 = toEquivalentEmailForm(email1);
  email2 = toEquivalentEmailForm(email2);
  return email1 === email2;
}

export function isEqualReact(a: any, b: any, options: { ignoreKeys?: string[]; functionsAreEqual?: boolean } = {}) {
  return isEqual(a, b, {
    functionsAreEqual: true,
    ignoreKeys: (options.ignoreKeys != null ? options.ignoreKeys : []).concat(["id"]),
  });
}

// Customized version of Underscore 1.8.2's isEqual function
// You can pass the following options:
//   - functionsAreEqual: if true then all functions are equal
//   - keysToIgnore: an array of object keys to ignore checks on
//   - logWhenFalse: logs when isEqual returns false
export function isEqual(
  a: any,
  b: any,
  options: { functionsAreEqual?: boolean; logWhenFalse?: boolean; ignoreKeys?: string[] } = {}
) {
  const value = _isEqual(a, b, [], [], options);
  if (options.logWhenFalse) {
    if (value === false) {
      console.log("isEqual is false", a, b, options);
    }
    return value;
  }
  return value;
}

export function _isEqual(
  a: any,
  b: any,
  aStack?: any[],
  bStack?: any[],
  options: { functionsAreEqual?: boolean; ignoreKeys?: string[] } = {}
) {
  // Identical objects are equal. `0 is -0`, but they aren't identical.
  // See the [Harmony `egal`
  // proposal](http://wiki.ecmascript.org/doku.php?id=harmony:egal).
  if (a === b) {
    return a !== 0 || 1 / a === 1 / b;
  }
  // A strict comparison is necessary because `null == undefined`.
  if (a === null || b === null) {
    return a === b;
  }
  // Unwrap any wrapped objects.
  if ((a != null ? a._wrapped : undefined) != null) {
    a = a._wrapped;
  }
  if ((b != null ? b._wrapped : undefined) != null) {
    b = b._wrapped;
  }

  if (options.functionsAreEqual) {
    if (_.isFunction(a) && _.isFunction(b)) {
      return true;
    }
  }

  // Compare `[[Class]]` names.
  const className = objToString.call(a);
  if (className !== objToString.call(b)) {
    return false;
  }
  switch (className) {
    // Strings, numbers, regular expressions, dates, and booleans are
    // compared by value.
    // RegExps are coerced to strings for comparison (Note: '' + /a/i is '/a/i')
    case "[object RegExp]":
    case "[object String]":
      // Primitives and their corresponding object wrappers are equivalent;
      // thus, `"5"` is equivalent to `new String("5")`.
      return `${a}` === `${b}`;
    case "[object Number]":
      // `NaN`s are equivalent, but non-reflexive.
      // Object(NaN) is equivalent to NaN
      if (+a !== +a) {
        return +b !== +b;
      }
      // An `egal` comparison is performed for other numeric values.
      if (+a === 0) {
        return 1 / +a === 1 / b;
      } else {
        return +a === +b;
      }
    case "[object Date]":
    case "[object Boolean]":
      // Coerce dates and booleans to numeric primitive values. Dates are
      // compared by their millisecond representations. Note that invalid
      // dates with millisecond representations of `NaN` are not
      // equivalent.
      return +a === +b;
    default:
  }

  const areArrays = className === "[object Array]";
  if (!areArrays) {
    if (typeof a !== "object" || typeof b !== "object") {
      return false;
    }

    // Objects with different constructors are not equivalent, but
    // `Object`s or `Array`s from different frames are.
    const aCtor = a.constructor;
    const bCtor = b.constructor;
    if (
      aCtor !== bCtor &&
      !(
        _.isFunction(aCtor) &&
        aCtor instanceof aCtor &&
        _.isFunction(bCtor) &&
        bCtor instanceof bCtor
      ) &&
      "constructor" in a &&
      "constructor" in b
    ) {
      return false;
    }
  }
  // Assume equality for cyclic structures. The algorithm for detecting cyclic
  // structures is adapted from ES 5.1 section 15.12.3, abstract operation `JO`.

  // Initializing stack of traversed objects.
  // It's done here since we only need them for objects and arrays comparison.
  aStack = aStack != null ? aStack : [];
  bStack = bStack != null ? bStack : [];
  let { length } = aStack;
  while (length--) {
    // Linear search. Performance is inversely proportional to the number of
    // unique nested structures.
    if (aStack[length] === a) {
      return bStack[length] === b;
    }
  }

  // Add the first object to the stack of traversed objects.
  aStack.push(a);
  bStack.push(b);

  // Recursively compare objects and arrays.
  if (areArrays) {
    // Compare array lengths to determine if a deep comparison is necessary.
    ({ length } = a);
    if (length !== b.length) {
      return false;
    }
    // Deep compare the contents, ignoring non-numeric properties.
    while (length--) {
      if (!_isEqual(a[length], b[length], aStack, bStack, options)) {
        return false;
      }
    }
  } else {
    // Deep compare objects.
    let key = undefined;
    const keys = Object.keys(a);
    ({ length } = keys);
    // Ensure that both objects contain the same number of properties
    // before comparing deep equality.
    if (Object.keys(b).length !== length) {
      return false;
    }
    const keysToIgnore: Record<string, boolean> = {};
    if (options.ignoreKeys && _.isArray(options.ignoreKeys)) {
      for (const ignored of options.ignoreKeys) {
        keysToIgnore[ignored] = true;
      }
    }
    while (length--) {
      // Deep compare each member
      key = keys[length];
      if (key in keysToIgnore) {
        continue;
      }
      if (!(_.has(b, key) && _isEqual(a[key], b[key], aStack, bStack, options))) {
        return false;
      }
    }
  }
  // Remove the first object from the stack of traversed objects.
  aStack.pop();
  bStack.pop();
  return true;
}
