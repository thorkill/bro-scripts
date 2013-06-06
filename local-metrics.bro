
@load base/frameworks/notice
@load base/frameworks/metrics

module Metrics;

export {

    ## Reset data from a :bro:type:`Metrics::ID`.
    ##
    ## id: The metric ID from which the data should be removed.
    ##
    ## index: The metric index to remove
    global reset_data: function(id: ID, index: Index);

}

function reset_data(id: ID, index: Index)
	{
	if ( id !in metric_filters )
		return;
	
	local filters = metric_filters[id];
	
	# Try to add the data to all of the defined filters for the metric.
	for ( filter_id in filters )
		{
		local filter = filters[filter_id];
		
		# If this filter has a predicate, run the predicate and skip this
		# index if the predicate return false.
		if ( filter?$pred && ! filter$pred(index) )
			next;
		
		local metric_tbl = store[id, filter$name];
        if ( index in metric_tbl )
			metric_tbl[index] = 0;
		}
	}
