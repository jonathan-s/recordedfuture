A few comments at the start of new phantom version - this time using git and docker for development:

There seems to be a clash of networks: restart docker deamon and rf_phantom to gets it working. 



# Phantom integration

Phantom is a System Orchestration and Automated Response (SOAR) platform 
owned by Splunk.

This repository is organized differently from most because in addition to
the integration app itself Recorded Future also provides a number of 
Playbooks to be used in the product. If our app is providing a few new
Lego blocks to the Phantom system, the playbooks are assemblies of Lego
blocks that provide some functionality.

The overall organization of the repository:
 - `releases`: binary packages of the official releases (this is actually 
   not entirely true since Phantom apps are kept in Phantoms official 
   GitHub repository)
 - `releases-playbooks`: binary packages of the "official" demo playbooks
- `docker`: config files for Docker that will launch development machines
- `src`:
  - `playbooks`: source for the "official" playbooks created for 
    demonstration purposes
  - `recordedfuture`: the actual app source code (Python, JSON, HTML and CSS)
  - `test`: test scripts
    - `playbooks`: special playbooks used by the test scripts
    - `testdata`: some data used for testing
    
# Developing Phantom

## Getting started
1. You need an account on https://my.phantom.us where all the documentation 
   lives. If you don't have an account, go there an sign-up. There is a 
   short waiting time before the account is activated upon registration.
1. You need a dev Phantom server (either through 
   `launch_int_instance phantom dev` for aws instance or 
   `docker-compose start rf_phantom` in the docker directory).<br />
1. You need to setup easy network access:<br/>
   `env PH=<your phantom dev machine> make setup_ssh` for aws instance or 
   `make setup_docker` for docker instance<br />
    This will add your ssh key to the autorized_keys of the 
   phantom user on the dev machine.

## Developing

To build and test the app:
1. Go to the src folder
 - For AWS instance, type `make PH=<your phantom dev machine> package`
 - For docker instance, type `make PH=<your phantom dev machine> PH_PORT=2022 package`

## Testing

1. Log in to the dev machine using your web browser. Go to Administration->
   User and select (edit) the automation user. Copy the authorization token.
1. Install and activate the test playbooks 
   1. Run `make playbooks` in src/test/playbooks
   2. Go to Playbooks on the Phantom server web GUI and click on "Import playbook".
      The playbook package are in the same folder as above.
1. Run the tests, ex:<br/>
   `env PH=<your phantom dev machine> PTOK=<the authorization token> nosetests`<br/>
   This assumes you have an environment variable RF_TOKEN with you Recorded Future 
   API key. If you don't that needs to be added.
   
### How the tests work

1. The tests makes calls to RFs API to fetch entities with high risk (using the 
RF_TOKEN token). 
1. Using these, 
new events are created on the Phantom system (using PTOK) where these 
entities are
stored as artifacts. In addition to the dangerous ons a few non existing
ones are also created to check behaviour if RF do not have any information.
1. When new events are created, any active playbook is run if tagging matches
   the event.
1. The test script looks for results from the playbook runs (it can timeout but 
   that is typically a sign of other issues).
1. Playbook result is read by the script and some checks are performed.

# Releasing a Phantom version

Releasing a Phantom version is done by making a pull request to Phantom's 
GitHub repository. They will then review the code before making a merge.

This process will change (as of 2020-09-18), we will be merging towards another
repository - details TBD.
