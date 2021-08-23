import React, { Component } from 'react'
import { WebView } from 'react-native-webview'

import { _buildColourCode } from '../utils/colour'

import Client from '../networking'

export default class AuthcoreScreen extends Component {
  constructor (props) {
    super(props)
    const {
      baseUrl,
      accessToken,
      company = undefined,
      logo = undefined,
      internal = false,
      page = 'profile',
      language = 'en'
    } = this.props

    let {
      primaryColour = undefined,
      dangerColour = undefined,
      successColour = undefined
    } = this.props

    if (accessToken === undefined) {
      console.warn('accessToken is undefined, please provide access token for normal access.')
    }
    this.client = new Client({
      baseUrl: baseUrl
    })

    const containerId = Math.random().toString(36).substring(2)
    primaryColour = _buildColourCode(primaryColour)
    successColour = _buildColourCode(successColour)
    dangerColour = _buildColourCode(dangerColour)
    if (typeof internal !== 'boolean') {
      throw new Error('internal param must be boolean')
    }

    this.widgetPath = this.client.url(`widgets/${page}`, {
      cid: containerId,
      company: company,
      logo: logo,
      primaryColour: primaryColour,
      successColour: successColour,
      dangerColour: dangerColour,
      internal: internal,
      language: language
    })
  }

  render () {
    const { accessToken, containerStyle } = this.props

    const injectAccessToken = `
      this.postMessage({type: 'AuthCore_accessToken', data: '${accessToken}'}, '${this.client.baseUrl}')
    `

    return (
      <WebView
        containerStyle={ containerStyle }
        source={{ uri: this.widgetPath }}
        injectedJavaScript={accessToken !== undefined && injectAccessToken}
        />
    )
  }
}
