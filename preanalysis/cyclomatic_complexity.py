import os

from sets import Set

def get_cyclomatic_complexity(function_ea):
    """Calculate the cyclomatic complexity measure for a function.
    
    Given the starting address of a function, it will find all
    the basic block's boundaries and edges between them and will
    return the cyclomatic complexity, defined as:
    
        CC = Edges - Nodes + 2
    """

    f_start = function_ea
    f_end = FindFuncEnd(function_ea)
    
    edges = Set()
    boundaries = Set((f_start,))
    
    # For each defined element in the function.
    for head in Heads(f_start, f_end):
    
        # If the element is an instruction
        if isCode(GetFlags(head)):
        
            # Get the references made from the current instruction
            # and keep only the ones local to the function.
            refs = CodeRefsFrom(head, 0)
            refs = Set(filter(lambda x: x>=f_start and x<=f_end, refs))
            
            if refs:
                # If the flow continues also to the next (address-wise)
                # instruction, we add a reference to it.
                # For instance, a conditional jump will not branch
                # if the condition is not met, so we save that
                # reference as well.
                next_head = NextHead(head, f_end)
                if isFlow(GetFlags(next_head)):
                    refs.add(next_head)
                
                # Update the boundaries found so far.
                boundaries.union_update(refs)
                            
                # For each of the references found, and edge is
                # created.
                for r in refs:
                    # If the flow could also come from the address
                    # previous to the destination of the branching
                    # an edge is created.
                    if isFlow(GetFlags(r)):
                        edges.add((PrevHead(r, f_start), r))
                    edges.add((head, r))

    return len(edges) - len(boundaries) + 2



