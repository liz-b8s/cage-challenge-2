# Copyright DST Group. Licensed under the MIT license.
from collections import namedtuple

from CybORG.Shared import Scenario
from CybORG.Shared.Actions import FindFlag, Impact
from CybORG.Shared.Actions.Action import Action
from CybORG.Shared.Enums import OperatingSystemType
from CybORG.Shared.RewardCalculator import RewardCalculator

WIN_REWARD = 0
LOSE_REWARD = 0
SESSION_REWARD = 0
ROOT_SESSION_REWARD = 0
LOSE_SESSION_REWARD = 0
LOSE_ROOT_SESSION_REWARD = 0

REWARD_MAX_DECIMAL_PLACES = 1

NEW_NONE = 0.0
NEW_LOW = 0.1
NEW_MEDIUM = 1.0
NEW_HIGH = 10.0

HostReward = namedtuple('HostReward', 'confidentiality availability')


def adjust_rewards(reward):
    # Manually setting the rewards
    if reward == 0.0:
        rs_alt_rew = NEW_NONE
        return (reward, rs_alt_rew)
    elif reward == 0.1:
        rs_alt_rew = NEW_LOW
        return (reward, rs_alt_rew)
    elif reward == 1.0:
        rs_alt_rew = NEW_MEDIUM
        return (reward, rs_alt_rew)
    elif reward == 10.0:
        rs_alt_rew = NEW_HIGH
        return (reward, rs_alt_rew)
    else:
        print("no reward")
        return (reward, 0)


class PwnRewardCalculator(RewardCalculator):
    # this reward calculator provides a reward to Red due to changes in the number of privileged sessions
    def __init__(self, agent_name: str, scenario: Scenario):
        super().__init__(agent_name)
        self.old_total = 0
        self.scenario = scenario
        self.mapping = {'None': 0.0,
                        'Low': 0.1,
                        'Medium': 1.0,
                        'High': 10.0}

        self.compromised_hosts = {}

    def reset(self):
        self.old_total = 0

    def calculate_reward(self, current_state: dict, action: dict, agent_observations: dict, done: bool):
        root_sessions_real = 0
        root_sessions_adjusted = 0
        system_sessions_real = 0
        system_sessions_adjusted = 0

        self.compromised_hosts = {}
        for host, info in current_state.items():
            if host == 'success':
                continue

            if 'Sessions' in info:
                for session in info['Sessions']:
                    if session['Agent'] == self.agent_name:
                        # count the number of root sessions
                        if session['Username'] == 'root' and info['System info']['OSType'] == OperatingSystemType.LINUX:
                            confidentiality_value = self.mapping[
                                self.scenario.get_host(host).get('ConfidentialityValue', 'Low')]
                            # print(f"conf value {confidentiality_value}")
                            confidentiality_value = adjust_rewards(confidentiality_value)
                            root_sessions_real += confidentiality_value[0]
                            root_sessions_adjusted += confidentiality_value[1]
                            self.compromised_hosts[host] = confidentiality_value[1]
                            break
                        # count the number of SYSTEM sessions
                        if session['Username'] == 'SYSTEM' and info['System info'][
                            'OSType'] == OperatingSystemType.WINDOWS:
                            confidentiality_value = self.mapping[
                                self.scenario.get_host(host).get('ConfidentialityValue', 'Low')]
                            confidentiality_value = adjust_rewards(confidentiality_value)
                            system_sessions_real += confidentiality_value[0]
                            system_sessions_adjusted += confidentiality_value[1]
                            self.compromised_hosts[host] = confidentiality_value[1]
                            break

        # find the difference from the old privileged sessions
        total_adjusted = root_sessions_adjusted + system_sessions_adjusted
        total_real = root_sessions_real + system_sessions_real

        reward_adjusted = total_adjusted  # - self.old_total
        reward_real = total_real
        # print(f"sum of availability scores (pawn):{round(reward_adjusted, REWARD_MAX_DECIMAL_PLACES), round(reward_real, REWARD_MAX_DECIMAL_PLACES)}")
        self.old_total = total_adjusted
        return round(reward_adjusted, REWARD_MAX_DECIMAL_PLACES), round(reward_real, REWARD_MAX_DECIMAL_PLACES)


class DistruptRewardCalculator(RewardCalculator):
    # calculates the reward for disrupting the network
    def __init__(self, agent_name: str, scenario: Scenario):
        super(DistruptRewardCalculator, self).__init__(agent_name)
        self.scenario = scenario
        self.ots = None
        self.mapping = {'None': 0.0,
                        'Low': 0.1,
                        'Medium': 1.0,
                        'High': 10.0}

        self.impacted_hosts = {}

    def reset(self):
        self.ots = None

    def calculate_reward(self, current_state: dict, action: dict, agent_observations: dict, done: bool):
        self.impacted_hosts = {}
        # currently a single 1 reward is recieved if the Impact action is successful
        # TODO: Add in test to see what required services are up
        agent_action = action[self.agent_name]
        disrupted = []
        if self.ots is None:
            self.ots = []
            for host_info in current_state.values():
                if type(host_info) is not dict:
                    continue
                if 'Processes' in host_info:
                    for proc in host_info['Processes']:
                        if proc['Process Name'] == 'OTService':
                            self.ots.append(host_info['System info']['Hostname'])
        for host_info in current_state.values():
            working = False
            if type(host_info) is not dict:
                continue
            if host_info['System info']['Hostname'] in self.ots:
                if 'Processes' in host_info:
                    for proc in host_info['Processes']:
                        if proc['Process Name'] == 'OTService':
                            working = True
                    if not working:
                        disrupted.append(host_info['System info']['Hostname'])
        # if type(agent_action) is Impact and agent_observations[self.agent_name].data['success'] == True:
        #     if agent_action.hostname not in disrupted:
        #         disrupted.append(agent_action.hostname)
        availability_scores_real = [self.mapping[self.scenario.get_host(i).get('AvailabilityValue', 'Low')] for i in
                                    disrupted]
        availability_scores_adjusted = [self.mapping[self.scenario.get_host(i).get('AvailabilityValue', 'Low')] for i in
                                        disrupted]
        for i in availability_scores_adjusted:
            i = adjust_rewards(i)
        self.impacted_hosts = dict(zip(disrupted, availability_scores_adjusted))
        reward_adjusted = sum(availability_scores_adjusted)
        reward_real = sum(availability_scores_real)
        # print(f"sum of availability scores (disrupt):{round(reward_adjusted, REWARD_MAX_DECIMAL_PLACES), round(reward_real, REWARD_MAX_DECIMAL_PLACES)}")
        return round(reward_adjusted, REWARD_MAX_DECIMAL_PLACES), round(reward_real, REWARD_MAX_DECIMAL_PLACES)


class HybridImpactPwnRewardCalculator(RewardCalculator):
    # Hybrid of availability and confidentiality reward calculator
    def __init__(self, agent_name: str, scenario: Scenario):
        super(HybridImpactPwnRewardCalculator, self).__init__(agent_name)
        self.pwn_calculator = PwnRewardCalculator(agent_name, scenario)
        self.disrupt_calculator = DistruptRewardCalculator(agent_name, scenario)
        self.host_scores = {}

    def reset(self):
        self.pwn_calculator.reset()
        self.disrupt_calculator.reset()

    def calculate_reward(self, current_state: dict, action: dict, agent_observations: dict, done: bool) -> float:
        reward = (self.pwn_calculator.calculate_reward(current_state, action, agent_observations, done)[0]
                  + self.disrupt_calculator.calculate_reward(current_state, action, agent_observations, done)[0],
                  self.pwn_calculator.calculate_reward(current_state, action, agent_observations, done)[1]
                  + self.disrupt_calculator.calculate_reward(current_state, action, agent_observations, done)[1])
        # print(f"this is the reward {reward}")
        self._compute_host_scores(current_state.keys())
        return round(reward[0], REWARD_MAX_DECIMAL_PLACES), round(reward[1], REWARD_MAX_DECIMAL_PLACES)

    def _compute_host_scores(self, hostnames):
        self.host_scores = {}
        compromised_hosts = self.pwn_calculator.compromised_hosts
        impacted_hosts = self.disrupt_calculator.impacted_hosts
        for host in hostnames:
            if host == 'success':
                continue
            compromised = compromised_hosts[host] if host in compromised_hosts else 0
            impacted = impacted_hosts[host] if host in impacted_hosts else 0
            reward_state = HostReward(compromised, impacted)
            # confidentiality, availability
            self.host_scores[host] = reward_state
