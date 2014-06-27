package tor.util;
import java.util.*;

/**
 * Thread unsafe implementation of UniqueQueue.
 */
public class UniqueQueue<T> implements Queue<T> {
  private final Queue<T> queue = new LinkedList<T>();
  private final Set<T> set = new HashSet<T>();

  public boolean add(T t) {
    // Only add element to queue if the set does not contain the specified element.
    if (set.add(t)) {
      queue.add(t);
    }

    return true; // Must always return true as per API def.
  }

  public T remove() throws NoSuchElementException {
    T ret = queue.remove();
    set.remove(ret);
    return ret;
  }

  @Override
  public boolean isEmpty() {
  	// TODO Auto-generated method stub
  	return set.isEmpty();
  }
  
  // WARNING - following not implemented
@Override
public boolean addAll(Collection<? extends T> arg0) {
	// TODO Auto-generated method stub
	return false;
}

@Override
public void clear() {
	// TODO Auto-generated method stub
	
}

@Override
public boolean contains(Object arg0) {
	// TODO Auto-generated method stub
	return false;
}

@Override
public boolean containsAll(Collection<?> arg0) {
	// TODO Auto-generated method stub
	return false;
}



@Override
public Iterator<T> iterator() {
	// TODO Auto-generated method stub
	return null;
}

@Override
public boolean remove(Object arg0) {
	// TODO Auto-generated method stub
	return false;
}

@Override
public boolean removeAll(Collection<?> arg0) {
	// TODO Auto-generated method stub
	return false;
}

@Override
public boolean retainAll(Collection<?> arg0) {
	// TODO Auto-generated method stub
	return false;
}

@Override
public int size() {
	// TODO Auto-generated method stub
	return 0;
}

@Override
public Object[] toArray() {
	// TODO Auto-generated method stub
	return null;
}

@Override
public <T> T[] toArray(T[] arg0) {
	// TODO Auto-generated method stub
	return null;
}

@Override
public T element() {
	// TODO Auto-generated method stub
	return null;
}

@Override
public boolean offer(T arg0) {
	// TODO Auto-generated method stub
	return false;
}

@Override
public T peek() {
	// TODO Auto-generated method stub
	return null;
}

@Override
public T poll() {
	// TODO Auto-generated method stub
	return null;
}

  // TODO: Implement other Queue methods.
}