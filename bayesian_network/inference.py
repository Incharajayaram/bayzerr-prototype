from pgmpy.inference import VariableElimination
from bayesian_network.network_builder import BayesianNetworkBuilder

class BayesianInference:
    """
    Performs probabilistic inference on the Bayesian Network to rank alarms and handle feedback.
    """

    def __init__(self, builder):
        """
        Args:
            builder (BayesianNetworkBuilder): An instance with a built BN.
        """
        self.builder = builder
        if builder.bn_model is None:
            raise ValueError("Bayesian Network not built. Call build_network() first.")
        
        self.inference_engine = VariableElimination(builder.bn_model)

    def compute_alarm_probabilities(self):
        """
        Computes the marginal probability P(Alarm=True) for all alarm nodes.
        
        Returns:
            dict: Mapping {alarm_node_id: probability_float}
        """
        # Identify alarm nodes
        alarm_nodes = [n for n in self.builder.bn_model.nodes() if n.startswith('Alarm')]
        results = {}
        
        # We can query all at once or one by one. 
        # Querying one by one is safer if the graph is disconnected or huge.
        # But joint query is not needed, we want marginals.
        
        for alarm in alarm_nodes:
            if alarm in self.builder.evidence:
                # If we already have evidence for this alarm, use it.
                # Evidence dict stores 1 (True) or 0 (False)
                results[alarm] = float(self.builder.evidence[alarm])
                continue

            try:
                # Query P(Alarm | Evidence)
                query_result = self.inference_engine.query(
                    variables=[alarm], 
                    evidence=self.builder.evidence
                )
                # Extract P(Alarm=1)
                # values is [P(0), P(1)]
                prob = query_result.values[1]
                results[alarm] = prob
            except Exception as e:
                print(f"Inference failed for {alarm}: {e}")
                results[alarm] = 0.0
                
        return results

    def rank_alarms(self):
        """
        Returns a list of (alarm_node, probability) tuples sorted by probability descending.
        """
        probs = self.compute_alarm_probabilities()
        # Sort by probability descending
        sorted_alarms = sorted(probs.items(), key=lambda item: item[1], reverse=True)
        return sorted_alarms

    def update_with_feedback(self, alarm_node, is_true_bug):
        """
        Updates the network with user feedback.
        
        Args:
            alarm_node (str): The alarm node ID.
            is_true_bug (bool): True if user confirmed it's a bug, False if false positive.
        """
        # If is_true_bug is True, we set Alarm=1.
        # If is_true_bug is False, we set Alarm=0.
        self.builder.set_evidence(alarm_node, is_true_bug)

    def reset_negative_evidence(self):
        """
        Clears all evidence where variables were set to False (0).
        Useful for 'what-if' analysis or clearing user rejections.
        """
        # Iterate over copy of keys
        for node, value in list(self.builder.evidence.items()):
            if value == 0:
                self.builder.clear_evidence(node)
