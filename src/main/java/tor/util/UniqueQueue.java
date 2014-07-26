/*
        Tor Research Framework - easy to use tor client library/framework
        Copyright (C) 2014  Dr Gareth Owen <drgowen@gmail.com>
        www.ghowen.me / github.com/drgowen/tor-research-framework

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
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