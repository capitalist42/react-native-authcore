import React, { Component } from 'react'
import AuthcoreScreen from './AuthcoreScreen'

export default class ProfileScreen extends Component {
  render () {
    return (
      <AuthcoreScreen
        baseUrl={ this.props.baseUrl }
        page={ 'profile' }
        accessToken={ this.props.accessToken }
        company={ this.props.company }
        logo={ this.props.logo }
        primaryColour={ this.props.primaryColour }
        successColour={ this.props.successColour }
        dangerColour={ this.props.dangerColour }
        internal={ this.props.internal }
        language={ this.props.language }
      />
    )
  }
}
