# react-native-authcore

## Getting started

`$ npm install react-native-authcore --save`

### Mostly automatic installation

`$ react-native link react-native-authcore`

### Manual installation


#### iOS

1. In XCode, in the project navigator, right click `Libraries` ➜ `Add Files to [your project's name]`
2. Go to `node_modules` ➜ `react-native-authcore` and add `Authcore.xcodeproj`
3. In XCode, in the project navigator, select your project. Add `libAuthcore.a` to your project's `Build Phases` ➜ `Link Binary With Libraries`
4. Run your project (`Cmd+R`)<

#### Android

1. Open up `android/app/src/main/java/[...]/MainApplication.java`
  - Add `import com.reactlibrary.AuthcorePackage;` to the imports at the top of the file
  - Add `new AuthcorePackage()` to the list returned by the `getPackages()` method
2. Append the following lines to `android/settings.gradle`:
  	```
  	include ':react-native-authcore'
  	project(':react-native-authcore').projectDir = new File(rootProject.projectDir, 	'../node_modules/react-native-authcore/android')
  	```
3. Insert the following lines inside the dependencies block in `android/app/build.gradle`:
  	```
      compile project(':react-native-authcore')
  	```


## Usage

Authcore module for React Native
```javascript
import Authcore from 'react-native-authcore';

Authcore;
```

## Widgets

This module provide profile and settings widget for user information. Developers can use the widget without implementating the API access for changing profile or security settings themselves.

To use the widget, Authcore instance must be instantiated first as it requires the hosting for the widget.

Example code:

```javascript
import Authcore from 'react-native-authcore';

const authcore = new Authcore({
  baseUrl: 'https://authcore.example.com'
})

...

render () {
  return (
    <authcore.ProfileScreen accessToken={ accessToken } />
  )
}
```

With state management, the authcore instance should be in the store, use that instance for screen requires using widget.

Screen provided
---

`ProfileScreen`
---
Screen for user profile.

`SettingsScreen`
---
Screen for user setting, mainly about security setting. Also including devices and social login information for the user.

Props Index
---

Props for modifying the layout of the widget to be shown.

* `company`: Company to be seen in the widget.
* `logo`: Logo to be seen in the widget, should be in absolute path format.
* `primaryColour`: The primary colour of the widget. Primary colour mainly consists of general button colour, link colour and border colour when the field box is in focus. Allow colour code, rgb colour value or named colour.
* `successColour`: The success colour of the widget. Success colour mainly consists of verified message and icon. Allow colour code, rgb colour value or named colour.
* `dangerColour`: The danger colour of the widget. Danger colour mainly consists of error message, button colour for destructive action (e.g. Remove contact) and invalid field box border. Allow colour code, rgb colour value or named colour.
* `language`: Language of the widget. It has filter which ensure the language is provided in the widget.

## Notes in current implementation

* Using `fetch` API as `authcore-js` package requires `crypto` package, which does not have in native browser. This may change when `authcore-js` is packed
* For local development using simulator, it is better to use the module requires `baseUrl` as
  `http://localhost:8000`(for iOS)/`http://10.0.2.2:8000`(for Android) without SSL. This is due to using `fetch` package in native with SSL require signed certificate

## To be noted
* iOS/Android additional information in using module
