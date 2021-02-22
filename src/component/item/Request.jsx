import React, { Component } from 'react';
import './Request.css';
import Popup from "reactjs-popup";
import {NotificationManager as nm} from 'react-notifications';
import {getRequest, postRequest} from '../../utils/request';
import User from '../item/User';
import FormLine from '../button/FormLine';
import Loading from '../box/Loading';
import DialogConfirmation from '../dialog/DialogConfirmation';
import Message from "../box/Message";
import { getApiURL } from '../../utils/env';


export default class Request extends Component {

    constructor(props) {
        super(props);

        this.onClick = this.onClick.bind(this);
        this.onClose = this.onClose.bind(this);
        this.onOpen = this.onOpen.bind(this);

        this.state = {
            request: null,
            user: null,
            requestStatus: null,
        }
    }

    onClick() {
        if (typeof this.props.disabled !== "undefined" || !this.props.disabled) {
            this.onOpen();

            let newState = !this.props.selected;
            if (typeof this.props.onClick !== "undefined")
                this.props.onClick(this.props.id, newState);
        }
    };

    onClose() {
        this.setState({ isDetailOpened: false });
    }

    onOpen() {
        this.setState({ 
            request: this.props.info,
            isDetailOpened: true, 
            user: null 
        });

        getRequest.call(this, "user/get_user/" + this.props.info.user_id, data => {
            this.setState({
                user: data
            });
        }, response => {
            nm.warning(response.statusText);
        }, error => {
            nm.error(error.message);
        });

        getRequest.call(this, "request/get_request_enums", data => {
            this.setState({
                requestStatus: data["status"]
            });
        }, response => {
            nm.warning(response.statusText);
        }, error => {
            nm.error(error.message);
        });
    }

    updateRequest(prop, value) {
        if (this.state.request[prop] !== value) {
            let params = {
                id: this.props.info.id,
                [prop]: value,
            }

            postRequest.call(this, "request/update_request", params, response => {
                let request = Object.assign({}, this.state.request);

                request[prop] = value;
                this.setState({ request: request });
                nm.info("The property has been updated");
            }, response => {
                nm.warning(response.statusText);
            }, error => {
                nm.error(error.message);
            });
        }
    }

    render() {
        return (
            <Popup
                className="Popup-small-size"
                trigger={
                    <div className={"Request"}>
                        <i className="fas fa-thumbtack"/>
                        <div className={"Request-name"}>
                            {this.props.info !== undefined && this.props.info !== null ?
                                this.props.info.submission_date
                            : 
                                "Unfound request"
                            }

                        </div>
                        {this.props.info !== undefined && this.props.info !== null ?
                            <div className={"Request-status"}>{this.props.info.status}</div>
                        : 
                            ""
                        }
                    </div>
                }
                modal
                closeOnDocumentClick
                onClose={this.onClose}
                onOpen={this.onOpen}
            >
                <div className="row row-spaced">
                    <div className="col-md-12">
                        <h2>
                            {this.props.info !== undefined && this.props.info !== null ?
                                "Request " + this.props.info.submission_date 
                                : 
                                "Unfound request"
                            }
                        </h2>
                    </div>

                    <div className="col-md-12">
                        {this.state.user !== null ?
                            <FormLine
                                label={"Status"}
                                type={"select"}
                                value={this.state.request.status}
                                options={this.state.requestStatus !== null ?
                                    this.state.requestStatus.map(v => { return {label: v, value: v}})
                                    : []}
                                onChange={v => this.updateRequest("status", v)}
                            />
                        : 
                            <Loading
                                height={100}
                            />
                        }
                        
                    </div>

                    <div className="col-md-12">
                        <h3>User</h3>
                        {this.state.user !== null ?
                            <User
                                id={this.state.user.id}
                                email={this.state.user.email}
                            />
                        : 
                            <Loading
                                height={100}
                            />
                        }

                        <h3>Content</h3>
                        {this.props.info !== undefined && this.props.info !== null ?
                            this.props.info.request 
                            : 
                            <Message
                                text={"Unfound request content"}
                                height={250}
                            />
                        }
                    </div>
                </div>
            </Popup>
        );
    }
}